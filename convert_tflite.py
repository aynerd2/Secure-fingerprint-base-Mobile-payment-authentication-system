"""
SFMPAS - convert the trained PAD model to full-integer (INT8) TFLite for Android.

  input  : uint8  [1, 224, 224, 3]   CLAHE-enhanced fingerprint, resized to 224,
                                     grayscale replicated across all 3 channels
  output : float32 [1, 1]            liveness score, 1.0 = genuine, 0.0 = attack

All internal ops run in INT8; a quantize op on the input and a dequantize op on
the output keep the app-facing tensors convenient. Calibration uses images drawn
from the TRAINING split only -- never test -- so the held-out evaluation stays
honest.

Usage:
    python convert_tflite.py
    python convert_tflite.py --checkpoint <path> --out <path> --calib 500
"""

import os
import sys
import json
import time
import random
import argparse
import importlib.util

import numpy as np

ROOT = os.path.dirname(os.path.abspath(__file__))

spec = importlib.util.spec_from_file_location("tp", os.path.join(ROOT, "train_pad.py"))
tp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tp)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--checkpoint",
                    default=os.path.join(ROOT, "outputs", "clahe_subject_disjoint",
                                         "best_checkpoint.keras"))
    ap.add_argument("--out", default=os.path.join(ROOT, "sfmpas_pad.tflite"))
    ap.add_argument("--calib", type=int, default=500,
                    help="number of TRAINING images used for INT8 calibration")
    ap.add_argument("--split", default="subject")
    ap.add_argument("--gabor", action="store_true",
                    help="model was trained WITH Gabor (default: CLAHE-only)")
    ap.add_argument("--threshold", type=float, default=0.5)
    args = ap.parse_args()

    import tensorflow as tf

    tp.banner("SFMPAS | Keras -> TFLite INT8")
    tp.log("checkpoint : {}".format(args.checkpoint))
    tp.log("output     : {}".format(args.out))

    # ---- rebuild the exact deterministic data split -----------------------
    paths, labels, groups, subjects, alterations = tp.build_inventory(
        6000, random.Random(tp.SEED))
    X = tp.preprocess_cache(paths, "full", args.gabor)
    tr, va, te = tp.make_split(labels, subjects, args.split, 0.20, 0.10)

    model = tf.keras.models.load_model(args.checkpoint, compile=False)
    tp.log("loaded Keras model: {:,} params".format(model.count_params()))

    # ---- calibration set: TRAINING images only ----------------------------
    rng = np.random.default_rng(tp.SEED)
    calib_idx = rng.choice(tr, size=min(args.calib, len(tr)), replace=False)
    tp.log("calibration set: {} images sampled from the TRAIN split "
           "(never test)".format(len(calib_idx)))

    def representative_dataset():
        for i in calib_idx:
            img = np.asarray(X[int(i)], dtype=np.float32)     # (224,224) [0,255]
            img = np.repeat(img[..., None], 3, axis=-1)       # (224,224,3)
            yield [img[None, ...]]                            # (1,224,224,3)

    # ---- convert ----------------------------------------------------------
    tp.banner("Converting (full integer quantisation)")
    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    converter.optimizations = [tf.lite.Optimize.DEFAULT]
    converter.representative_dataset = representative_dataset
    converter.target_spec.supported_ops = [tf.lite.OpsSet.TFLITE_BUILTINS_INT8]
    # uint8 in (raw image bytes from the camera pipeline), float32 out (probability)
    converter.inference_input_type = tf.uint8
    converter.inference_output_type = tf.float32

    t0 = time.time()
    tflite_model = converter.convert()
    tp.log("converted in {:.1f}s".format(time.time() - t0))

    with open(args.out, "wb") as f:
        f.write(tflite_model)

    keras_size = os.path.getsize(args.checkpoint)
    tfl_size = os.path.getsize(args.out)
    tp.log("Keras checkpoint : {:8.2f} MB".format(keras_size / 1e6))
    tp.log("TFLite INT8      : {:8.2f} MB  ({:.1f}x smaller)".format(
        tfl_size / 1e6, keras_size / tfl_size))

    # ---- inspect the resulting signature ----------------------------------
    # The desktop XNNPACK delegate refuses to prepare this int8 graph, so fall
    # back to the plain builtin resolver. This affects only local verification;
    # the .tflite file itself is unchanged, and Android picks its own delegate.
    try:
        interp = tf.lite.Interpreter(model_content=tflite_model)
        interp.allocate_tensors()
        tp.log("interpreter: default delegates (XNNPACK) OK")
    except RuntimeError as e:
        tp.log("XNNPACK delegate unavailable ({}); using builtin resolver "
               "without default delegates".format(str(e).splitlines()[0][:60]))
        interp = tf.lite.Interpreter(
            model_content=tflite_model,
            experimental_op_resolver_type=(
                tf.lite.experimental.OpResolverType.BUILTIN_WITHOUT_DEFAULT_DELEGATES))
        interp.allocate_tensors()
    inp = interp.get_input_details()[0]
    out = interp.get_output_details()[0]
    tp.banner("TFLite signature")
    for name, d in (("INPUT", inp), ("OUTPUT", out)):
        print("  {:<7} name={} shape={} dtype={}".format(
            name, d["name"], list(d["shape"]), np.dtype(d["dtype"]).name))
        sc, zp = d["quantization"]
        if sc:
            print("          quantization: scale={:.8f} zero_point={}".format(sc, zp))
    ops = set()
    try:
        for op in interp._get_ops_details():
            ops.add(op["op_name"])
        print("  ops: {}".format(", ".join(sorted(ops))))
    except Exception:
        pass

    # ---- verify on the held-out test set ----------------------------------
    tp.banner("VERIFICATION | TFLite INT8 vs Keras float32 on held-out test set")
    y_true = labels[te]

    # Keras reference
    def keras_scores():
        AUTO = tf.data.AUTOTUNE
        ds = tf.data.Dataset.from_tensor_slices(te.astype(np.int64)).batch(64)

        def fetch(ii):
            def _read(a):
                return np.ascontiguousarray(X[a], dtype=np.uint8)
            img = tf.numpy_function(_read, [ii], tf.uint8)
            img.set_shape([None, tp.IMG_SIZE, tp.IMG_SIZE])
            img = tf.cast(img, tf.float32)
            return tf.repeat(img[..., None], 3, axis=-1)

        ds = ds.map(fetch, num_parallel_calls=AUTO).prefetch(AUTO)
        return model.predict(ds, verbose=0).ravel()

    t0 = time.time()
    s_keras = keras_scores()
    tp.log("Keras inference on {} test images: {:.1f}s".format(len(te), time.time() - t0))

    # TFLite inference (single-sample, as it will run on device)
    s_tfl = np.zeros(len(te), dtype=np.float32)
    t0 = time.time()
    for n, i in enumerate(te):
        img = np.asarray(X[int(i)], dtype=np.uint8)
        img = np.repeat(img[..., None], 3, axis=-1)[None, ...]
        interp.set_tensor(inp["index"], img)
        interp.invoke()
        s_tfl[n] = float(interp.get_tensor(out["index"]).ravel()[0])
        if (n + 1) % 1000 == 0:
            tp.log("  tflite {}/{}".format(n + 1, len(te)))
    dt = time.time() - t0
    tp.log("TFLite inference: {:.1f}s total, {:.2f} ms/image (desktop CPU, "
           "batch=1)".format(dt, dt / len(te) * 1000))

    m_k = tp.pad_metrics(y_true, s_keras, groups[te], alterations[te], args.threshold)
    m_t = tp.pad_metrics(y_true, s_tfl, groups[te], alterations[te], args.threshold)

    print("")
    print("  {:<24}{:>14}{:>14}{:>12}".format("metric", "Keras fp32", "TFLite INT8", "delta"))
    print("  " + "-" * 64)
    rows = [("APCER %", "apcer", 100), ("BPCER %", "bpcer", 100),
            ("ACER %", "acer", 100), ("accuracy %", "accuracy", 100),
            ("ROC AUC", "roc_auc", 1), ("EER %", "eer", 100),
            ("worst-case PAI %", "apcer_max_pai", 100)]
    for label, key, mul in rows:
        a, b = m_k[key] * mul, m_t[key] * mul
        fmt = "{:>14.5f}" if mul == 1 else "{:>14.4f}"
        print(("  {:<24}" + fmt + fmt + "{:>+12.4f}").format(label, a, b, b - a))

    agree = float((( s_keras >= args.threshold) == (s_tfl >= args.threshold)).mean())
    print("")
    print("  decision agreement (thr {:.2f}) : {:.4f} %  ({} of {} images differ)".format(
        args.threshold, agree * 100, int((1 - agree) * len(te)), len(te)))
    print("  max |score difference|          : {:.6f}".format(
        float(np.abs(s_keras - s_tfl).max())))
    print("  mean |score difference|         : {:.6f}".format(
        float(np.abs(s_keras - s_tfl).mean())))

    rep = {
        "tflite_path": args.out,
        "tflite_bytes": tfl_size,
        "keras_checkpoint": args.checkpoint,
        "calibration_images": int(len(calib_idx)),
        "calibration_source": "train split only",
        "input": {"dtype": "uint8", "shape": [1, tp.IMG_SIZE, tp.IMG_SIZE, 3],
                  "range": "0-255, CLAHE-enhanced grayscale replicated to 3 channels"},
        "output": {"dtype": "float32", "shape": [1, 1],
                   "meaning": "liveness score; >= threshold => genuine"},
        "threshold": args.threshold,
        "keras_metrics": {k: m_k[k] for k in
                          ("apcer", "bpcer", "acer", "accuracy", "roc_auc", "eer")},
        "tflite_metrics": {k: m_t[k] for k in
                           ("apcer", "bpcer", "acer", "accuracy", "roc_auc", "eer")},
        "decision_agreement": agree,
        "ms_per_image_desktop_cpu": dt / len(te) * 1000,
    }
    rep_path = os.path.join(ROOT, "outputs", "tflite_conversion_report.json")
    with open(rep_path, "w") as f:
        json.dump(rep, f, indent=2)
    tp.log("wrote {}".format(rep_path))
    tp.banner("DONE")


if __name__ == "__main__":
    main()
