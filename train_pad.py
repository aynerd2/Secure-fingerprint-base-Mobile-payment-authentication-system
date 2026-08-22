"""
SFMPAS - Fingerprint Presentation Attack Detection (Liveness Detection)
=======================================================================
MSc dissertation pipeline: SOCOFing Real vs Altered fingerprint classification
using Gabor ridge enhancement + MobileNetV3-Small transfer learning.

Pipeline
--------
  1. Undersample fakes to N per Altered difficulty subfolder (default 6000).
  2. Stratified 80/20 train/test split (optionally subject-disjoint).
  3. Gabor filter bank ridge enhancement (+ CLAHE), cached to disk.
  4. Resize to 224x224, replicate grayscale to 3 channels.
  5. MobileNetV3-Small, ImageNet pre-trained, fine-tuned end-to-end.
  6. Class weighting to suppress false rejection of genuine fingers (BPCER).
  7. Adam @ 1e-4 with cosine decay, up to 50 epochs + early stopping.
  8. ISO/IEC 30107-3 style APCER / BPCER / ACER reporting.
  9. Training-curve PNG + saved model.

Labels:  1 = genuine (bona fide / live)      0 = altered (presentation attack)

Usage
-----
  python train_pad.py                          # full run, as specified
  python train_pad.py --limit 400 --epochs 2   # fast smoke test
  python train_pad.py --split subject          # identity-disjoint split
"""

import os
import sys
import json
import time
import math
import argparse
import hashlib
import random
from datetime import datetime

os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")

import numpy as np
import cv2
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
from sklearn.metrics import roc_curve, auc, confusion_matrix

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
ROOT      = os.path.dirname(os.path.abspath(__file__))
DATA_DIR  = os.path.join(ROOT, "fgpdataset")
REAL_DIR  = os.path.join(DATA_DIR, "Real")
ALT_DIR   = os.path.join(DATA_DIR, "Altered")
ALT_SUBS  = ["Altered-Easy", "Altered-Medium", "Altered-Hard"]

OUT_DIR   = os.path.join(ROOT, "outputs")
CACHE_DIR = os.path.join(ROOT, "cache")

IMG_SIZE  = 224
SEED      = 42

# Gabor bank (tuned for ~103x96 SOCOFing ridge spacing)
GABOR = dict(ksize=15, sigma=3.0, lambd=8.0, gamma=0.5, psi=0.0, n_orient=8)
CLAHE_CLIP, CLAHE_GRID = 2.0, (8, 8)


def log(msg):
    print("[{:%H:%M:%S}] {}".format(datetime.now(), msg), flush=True)


def banner(title):
    print("\n" + "=" * 78, flush=True)
    print("  " + title, flush=True)
    print("=" * 78, flush=True)


# --------------------------------------------------------------------------
# 1. Dataset inventory + undersampling
# --------------------------------------------------------------------------
def parse_meta(fname):
    """'100__M_Left_index_finger_CR.BMP' -> (subject, finger_id, alteration)."""
    stem = os.path.splitext(fname)[0]
    subject = stem.split("__")[0]
    alteration = "none"
    for tag in ("CR", "Obl", "Zcut"):
        if stem.endswith("_" + tag):
            alteration = tag
            stem = stem[: -(len(tag) + 1)]
            break
    return subject, stem, alteration


def list_bmps(folder):
    """Fast directory listing (os.scandir avoids the sort cost of listdir)."""
    out = []
    with os.scandir(folder) as it:
        for e in it:
            if e.is_file() and e.name.lower().endswith(".bmp"):
                out.append(e.name)
    out.sort()
    return out


def build_inventory(n_per_fake, rng, limit=None):
    """Return parallel arrays describing the (undersampled) dataset."""
    banner("STEP 1 | Dataset inventory & undersampling")

    paths, labels, groups, subjects, alterations = [], [], [], [], []

    real = list_bmps(REAL_DIR)
    log("Real (genuine, label 1) : {} BMP found -> using all {}".format(
        len(real), len(real)))
    for f in real:
        subj, fid, alt = parse_meta(f)
        paths.append(os.path.join(REAL_DIR, f))
        labels.append(1)
        groups.append("Real")
        subjects.append(subj)
        alterations.append(alt)

    for sub in ALT_SUBS:
        d = os.path.join(ALT_DIR, sub)
        files = list_bmps(d)
        take = min(n_per_fake, len(files))
        chosen = sorted(rng.sample(files, take))
        log("{:<16}(attack, label 0): {} BMP found -> undersampled to {}".format(
            sub, len(files), take))
        for f in chosen:
            subj, fid, alt = parse_meta(f)
            paths.append(os.path.join(d, f))
            labels.append(0)
            groups.append(sub)
            subjects.append(subj)
            alterations.append(alt)

    paths = np.array(paths)
    labels = np.array(labels, dtype=np.int32)
    groups = np.array(groups)
    subjects = np.array(subjects)
    alterations = np.array(alterations)

    if limit:  # smoke-test mode: stratified subsample of everything
        idx, _ = train_test_split(
            np.arange(len(labels)), train_size=min(limit, len(labels) - 2),
            stratify=labels, random_state=SEED)
        idx = np.sort(idx)
        paths, labels = paths[idx], labels[idx]
        groups, subjects, alterations = groups[idx], subjects[idx], alterations[idx]
        log("--limit active: reduced to {} images for smoke test".format(len(labels)))

    n_real = int((labels == 1).sum())
    n_fake = int((labels == 0).sum())
    log("TOTAL: {} images | genuine={} attack={} (ratio 1:{:.2f})".format(
        len(labels), n_real, n_fake, n_fake / max(n_real, 1)))
    return paths, labels, groups, subjects, alterations


# --------------------------------------------------------------------------
# 2. Gabor enhancement + cache
# --------------------------------------------------------------------------
def build_gabor_bank():
    ks = (GABOR["ksize"], GABOR["ksize"])
    return [
        cv2.getGaborKernel(ks, GABOR["sigma"], theta, GABOR["lambd"],
                           GABOR["gamma"], GABOR["psi"], ktype=cv2.CV_32F)
        for theta in np.arange(0, np.pi, np.pi / GABOR["n_orient"])
    ]


_BANK = None
_CLAHE = None


def enhance(path, use_gabor=True):
    """CLAHE -> [Gabor bank, max response over orientations] -> resize -> uint8.

    use_gabor=False gives the CLAHE-only ablation baseline. Gabor max-response is
    tuned to emphasise ridge FLOW, which may smooth over exactly the structural
    discontinuities (Z-cut, obliteration, central rotation) that mark an altered
    print -- so the ablation is the way to check whether it helps or hurts PAD.
    """
    global _BANK, _CLAHE
    if _BANK is None:
        _BANK = build_gabor_bank()
        _CLAHE = cv2.createCLAHE(clipLimit=CLAHE_CLIP, tileGridSize=CLAHE_GRID)

    img = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        raise IOError("Unreadable image: " + str(path))
    img = _CLAHE.apply(img)
    if not use_gabor:
        return cv2.resize(img, (IMG_SIZE, IMG_SIZE), interpolation=cv2.INTER_CUBIC)
    f32 = img.astype(np.float32)
    resp = np.max(np.stack([cv2.filter2D(f32, cv2.CV_32F, k) for k in _BANK]), axis=0)
    resp = cv2.normalize(resp, None, 0, 255, cv2.NORM_MINMAX)
    return cv2.resize(resp.astype(np.uint8), (IMG_SIZE, IMG_SIZE),
                      interpolation=cv2.INTER_CUBIC)


def preprocess_cache(paths, tag, use_gabor=True):
    """Gabor-enhance every image once and memory-map the result."""
    banner("STEP 2 | Gabor ridge enhancement + resize (cached)")
    os.makedirs(CACHE_DIR, exist_ok=True)

    # NB: the key for the Gabor case is left exactly as it was so previously
    # built caches stay valid; only the ablation adds a discriminator.
    key_src = "|".join(paths) + json.dumps(GABOR, sort_keys=True) + str(IMG_SIZE)
    if not use_gabor:
        key_src += "|nogabor"
    key = hashlib.md5(key_src.encode()).hexdigest()[:12]
    arr_path = os.path.join(CACHE_DIR, "{}_{}_{}.npy".format(
        "gabor" if use_gabor else "clahe", tag, key))

    if os.path.exists(arr_path):
        log("Cache HIT  -> {} (skipping preprocessing)".format(
            os.path.basename(arr_path)))
        return np.load(arr_path, mmap_mode="r")

    log("Cache MISS -> building {}".format(os.path.basename(arr_path)))
    if use_gabor:
        log("Gabor bank: {} orientations, ksize={}, sigma={}, lambda={}, gamma={}".format(
            GABOR["n_orient"], GABOR["ksize"], GABOR["sigma"],
            GABOR["lambd"], GABOR["gamma"]))
    else:
        log("ABLATION: Gabor DISABLED - CLAHE + resize only (baseline)")

    tmp = arr_path + ".tmp"
    mm = np.lib.format.open_memmap(tmp, mode="w+", dtype=np.uint8,
                                   shape=(len(paths), IMG_SIZE, IMG_SIZE))
    t0 = time.time()
    for i, p in enumerate(paths):
        mm[i] = enhance(p, use_gabor)
        if (i + 1) % 2000 == 0 or i + 1 == len(paths):
            el = time.time() - t0
            log("  enhanced {}/{}  ({:.0f}s, {:.0f} img/s)".format(
                i + 1, len(paths), el, (i + 1) / max(el, 1e-9)))
    mm.flush()
    del mm
    os.replace(tmp, arr_path)
    log("Cached {} images -> {} ({:.2f} GB)".format(
        len(paths), arr_path, os.path.getsize(arr_path) / 1e9))
    return np.load(arr_path, mmap_mode="r")


# --------------------------------------------------------------------------
# 3. Splitting
# --------------------------------------------------------------------------
def make_split(labels, subjects, mode, test_size, val_size):
    banner("STEP 3 | Train / validation / test split")
    idx = np.arange(len(labels))

    if mode == "subject":
        uniq = np.unique(subjects)
        tr_s, te_s = train_test_split(uniq, test_size=test_size, random_state=SEED)
        tr_s, va_s = train_test_split(tr_s, test_size=val_size, random_state=SEED)
        tr = idx[np.isin(subjects, tr_s)]
        va = idx[np.isin(subjects, va_s)]
        te = idx[np.isin(subjects, te_s)]
        log("Split mode: SUBJECT-DISJOINT (no subject appears in more than one split)")
    else:
        tr, te = train_test_split(idx, test_size=test_size,
                                  stratify=labels, random_state=SEED)
        tr, va = train_test_split(tr, test_size=val_size,
                                  stratify=labels[tr], random_state=SEED)
        log("Split mode: STRATIFIED RANDOM 80/20 (class-balanced)")
        shared = len(set(subjects[tr].tolist()) & set(subjects[te].tolist()))
        log("NOTE: {} subject IDs appear in BOTH train and test. Every Altered image "
            "is derived from".format(shared))
        log("      the Real image of the same subject/finger, so these test scores "
            "carry identity")
        log("      leakage and read optimistically. Re-run with --split subject for "
            "a leakage-free figure.")

    for name, s in (("train", tr), ("val", va), ("test", te)):
        g = int((labels[s] == 1).sum())
        a = int((labels[s] == 0).sum())
        log("  {:<5}: {:>6} images  (genuine={}, attack={})".format(
            name, len(s), g, a))
    log("Validation set is carved out of the 80% TRAIN portion, so the 20% TEST set "
        "stays fully held out.")
    return tr, va, te


# --------------------------------------------------------------------------
# 4. Model
# --------------------------------------------------------------------------
def build_model(tf, augment):
    banner("STEP 4 | MobileNetV3-Small (ImageNet transfer learning)")
    base = tf.keras.applications.MobileNetV3Small(
        input_shape=(IMG_SIZE, IMG_SIZE, 3),
        include_top=False,
        weights="imagenet",
        include_preprocessing=True,   # expects raw [0,255] input
        pooling="avg",
    )
    base.trainable = True   # full fine-tune: Gabor ridge maps are far from ImageNet

    inp = tf.keras.Input((IMG_SIZE, IMG_SIZE, 3), name="gabor_input")
    x = inp
    if augment:
        x = tf.keras.layers.RandomTranslation(0.06, 0.06, fill_mode="nearest")(x)
        x = tf.keras.layers.RandomRotation(0.04, fill_mode="nearest")(x)
        log("Augmentation ENABLED (small translation + rotation)")
    x = base(x)
    x = tf.keras.layers.Dropout(0.3, name="head_dropout")(x)
    out = tf.keras.layers.Dense(1, activation="sigmoid", name="liveness")(x)
    model = tf.keras.Model(inp, out, name="SFMPAS_MobileNetV3Small")

    trainable = sum(int(np.prod(w.shape)) for w in model.trainable_weights)
    log("Backbone: MobileNetV3-Small | ImageNet weights | all layers trainable")
    log("Total params: {:,} | trainable: {:,}".format(model.count_params(), trainable))
    return model


# --------------------------------------------------------------------------
# 5. Metrics (ISO/IEC 30107-3)
# --------------------------------------------------------------------------
def pad_metrics(y_true, y_score, groups, alterations, threshold=0.5):
    """APCER = attacks accepted as genuine.  BPCER = genuine rejected as attack."""
    y_pred = (y_score >= threshold).astype(int)
    atk = y_true == 0
    bon = y_true == 1

    apcer = float((y_pred[atk] == 1).mean()) if atk.any() else float("nan")
    bpcer = float((y_pred[bon] == 0).mean()) if bon.any() else float("nan")

    per_pai = {}
    for sub in ALT_SUBS:
        m = atk & (groups == sub)
        if m.any():
            per_pai[sub] = float((y_pred[m] == 1).mean())
    per_alt = {}
    for a in ("CR", "Obl", "Zcut"):
        m = atk & (alterations == a)
        if m.any():
            per_alt[a] = float((y_pred[m] == 1).mean())

    fpr, tpr, thr = roc_curve(y_true, y_score)
    roc_auc = float(auc(fpr, tpr))
    fnr = 1 - tpr
    i = int(np.nanargmin(np.abs(fnr - fpr)))
    eer = float((fpr[i] + fnr[i]) / 2)
    eer_thr = float(thr[i])

    # Operating points. Because the genuine class is up-weighted on purpose, the
    # 0.5 cut-off is not the interesting one; report the standard constrained
    # points so the APCER/BPCER trade-off can be read off directly.
    # Read the trade-off off the ROC curve itself: it enumerates exactly the
    # operating points the scores can actually realise, so this stays correct
    # when a confident sigmoid saturates many scores at 0 or 1 (which a naive
    # quantile on the raw scores does not).
    #   positive class = genuine  =>  fpr == APCER,  1 - tpr == BPCER
    def bpcer_at_apcer(target):
        """Lowest BPCER reachable while holding APCER <= target."""
        ok = np.where(fpr <= target + 1e-12)[0]
        if not len(ok):
            return float("nan"), float("nan")
        j = ok[int(np.argmax(tpr[ok]))]
        return float(1.0 - tpr[j]), float(thr[j])

    def apcer_at_bpcer(target):
        """Lowest APCER reachable while holding BPCER <= target."""
        ok = np.where((1.0 - tpr) <= target + 1e-12)[0]
        if not len(ok):
            return float("nan"), float("nan")
        j = ok[int(np.argmin(fpr[ok]))]
        return float(fpr[j]), float(thr[j])

    ops = {}
    for tgt in (0.01, 0.05, 0.10):
        b, tb = bpcer_at_apcer(tgt)
        a, ta = apcer_at_bpcer(tgt)
        ops["bpcer_at_apcer_{:g}pct".format(tgt * 100)] = dict(value=b, threshold=tb)
        ops["apcer_at_bpcer_{:g}pct".format(tgt * 100)] = dict(value=a, threshold=ta)

    y_eer = (y_score >= eer_thr).astype(int)
    at_eer = dict(
        threshold=eer_thr,
        apcer=float((y_eer[atk] == 1).mean()) if atk.any() else float("nan"),
        bpcer=float((y_eer[bon] == 0).mean()) if bon.any() else float("nan"),
        accuracy=float((y_eer == y_true).mean()),
    )
    at_eer["acer"] = (at_eer["apcer"] + at_eer["bpcer"]) / 2

    return dict(
        operating_points=ops, at_eer_threshold=at_eer,
        threshold=threshold,
        accuracy=float((y_pred == y_true).mean()),
        apcer=apcer, bpcer=bpcer, acer=(apcer + bpcer) / 2,
        apcer_max_pai=max(per_pai.values()) if per_pai else float("nan"),
        apcer_per_difficulty=per_pai, apcer_per_alteration=per_alt,
        roc_auc=roc_auc, eer=eer, eer_threshold=eer_thr,
        confusion=confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist(),
        n_attack=int(atk.sum()), n_bonafide=int(bon.sum()),
        _roc=(fpr.tolist(), tpr.tolist(), thr.tolist()),
    )


def print_report(m, hist_epochs, wall):
    banner("STEP 9 | RESULTS - ISO/IEC 30107-3 PAD METRICS")
    cm = m["confusion"]
    print("")
    print("  Operating threshold                 : {:.2f}".format(m["threshold"]))
    print("  Test images                         : {}  (attack={}, bona fide={})".format(
        m["n_attack"] + m["n_bonafide"], m["n_attack"], m["n_bonafide"]))
    print("")
    print("  " + "-" * 66)
    print("   APCER  (attacks wrongly ACCEPTED)  : {:8.4f} %".format(m["apcer"] * 100))
    print("   BPCER  (genuine wrongly REJECTED)  : {:8.4f} %".format(m["bpcer"] * 100))
    print("   ACER   ((APCER + BPCER) / 2)       : {:8.4f} %".format(m["acer"] * 100))
    print("  " + "-" * 66)
    print("")
    print("  Test accuracy                       : {:8.4f} %".format(m["accuracy"] * 100))
    print("  ROC AUC                             : {:8.6f}".format(m["roc_auc"]))
    print("  EER                                 : {:8.4f} %  (@ thr {:.4f})".format(
        m["eer"] * 100, m["eer_threshold"]))
    print("")
    ae = m["at_eer_threshold"]
    print("  At the EER / balanced threshold ({:.4f}):".format(ae["threshold"]))
    print("     APCER {:7.4f} %   BPCER {:7.4f} %   ACER {:7.4f} %   acc {:7.4f} %".format(
        ae["apcer"] * 100, ae["bpcer"] * 100, ae["acer"] * 100, ae["accuracy"] * 100))
    print("")
    print("  Constrained operating points (threshold-independent trade-off):")
    for tgt in (1, 5, 10):
        k = "bpcer_at_apcer_{}pct".format(tgt)
        if k in m["operating_points"]:
            o = m["operating_points"][k]
            print("     BPCER @ APCER<={:>2}%          : {:8.4f} %   (thr {:.4f})".format(
                tgt, o["value"] * 100, o["threshold"]))
    for tgt in (1, 5, 10):
        k = "apcer_at_bpcer_{}pct".format(tgt)
        if k in m["operating_points"]:
            o = m["operating_points"][k]
            print("     APCER @ BPCER<={:>2}%          : {:8.4f} %   (thr {:.4f})".format(
                tgt, o["value"] * 100, o["threshold"]))
    print("")
    print("  APCER per PAI species (difficulty):")
    for k, v in m["apcer_per_difficulty"].items():
        print("     {:<16} : {:8.4f} %".format(k, v * 100))
    print("     {:<16} : {:8.4f} %   (ISO 30107-3 headline APCER)".format(
        "WORST-CASE PAI", m["apcer_max_pai"] * 100))
    print("")
    print("  APCER per alteration type:")
    for k, v in m["apcer_per_alteration"].items():
        print("     {:<16} : {:8.4f} %".format(k, v * 100))
    print("")
    print("  Confusion matrix (rows=true, cols=pred, order [attack, genuine]):")
    print("     attack  -> [{:>6} correct, {:>6} accepted as genuine]".format(
        cm[0][0], cm[0][1]))
    print("     genuine -> [{:>6} rejected as attack, {:>6} correct]".format(
        cm[1][0], cm[1][1]))
    print("")
    print("  Epochs run: {}   |   Wall clock: {:.1f} min".format(hist_epochs, wall / 60))
    print("")


# --------------------------------------------------------------------------
# 6. Plots
# --------------------------------------------------------------------------
def plot_curves(hist, lrs, path):
    keys = [("loss", "Binary cross-entropy loss"),
            ("accuracy", "Accuracy"),
            ("auc", "ROC AUC"),
            ("recall", "Recall on genuine (1 - BPCER)")]
    fig, axes = plt.subplots(2, 3, figsize=(19, 10))
    fig.suptitle("SFMPAS - MobileNetV3-Small training curves", fontsize=16, y=0.98)
    ax = axes.ravel()
    for i, (k, title) in enumerate(keys):
        if k not in hist:
            ax[i].axis("off")
            continue
        ep = range(1, len(hist[k]) + 1)
        ax[i].plot(ep, hist[k], label="train", lw=1.8)
        if "val_" + k in hist:
            ax[i].plot(ep, hist["val_" + k], label="validation", lw=1.8)
        ax[i].set_title(title)
        ax[i].set_xlabel("epoch")
        ax[i].grid(alpha=.3)
        ax[i].legend()
    if lrs:
        ax[4].plot(range(1, len(lrs) + 1), lrs, color="tab:green", lw=1.8)
        ax[4].set_title("Learning rate (Adam + cosine decay)")
        ax[4].set_xlabel("epoch")
        ax[4].set_yscale("log")
        ax[4].grid(alpha=.3)
    else:
        ax[4].axis("off")
    if "precision" in hist:
        ep = range(1, len(hist["precision"]) + 1)
        ax[5].plot(ep, hist["precision"], label="train", lw=1.8)
        if "val_precision" in hist:
            ax[5].plot(ep, hist["val_precision"], label="validation", lw=1.8)
        ax[5].set_title("Precision on genuine")
        ax[5].set_xlabel("epoch")
        ax[5].grid(alpha=.3)
        ax[5].legend()
    else:
        ax[5].axis("off")
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)
    log("Saved training curves -> {}".format(path))


def plot_eval(m, y_true, y_score, path):
    fpr, tpr, _ = m["_roc"]
    fpr, tpr = np.array(fpr), np.array(tpr)
    fig, ax = plt.subplots(1, 3, figsize=(19, 5.5))

    ax[0].plot(fpr, tpr, lw=2, label="AUC = {:.5f}".format(m["roc_auc"]))
    ax[0].plot([0, 1], [0, 1], "k--", lw=1)
    ax[0].set_xlabel("APCER (false accept rate)")
    ax[0].set_ylabel("1 - BPCER (true accept rate)")
    ax[0].set_title("ROC")
    ax[0].legend()
    ax[0].grid(alpha=.3)

    ths = np.linspace(0.001, 0.999, 400)
    ap = [(y_score[y_true == 0] >= t).mean() for t in ths]
    bp = [(y_score[y_true == 1] < t).mean() for t in ths]
    ax[1].plot(ths, np.array(ap) * 100, label="APCER")
    ax[1].plot(ths, np.array(bp) * 100, label="BPCER")
    ax[1].axvline(0.5, ls="--", c="grey", lw=1, label="operating thr = 0.5")
    ax[1].set_xlabel("decision threshold")
    ax[1].set_ylabel("error rate (%)")
    ax[1].set_title("APCER / BPCER vs threshold")
    ax[1].legend()
    ax[1].grid(alpha=.3)

    ax[2].hist(y_score[y_true == 0], bins=60, alpha=.65, label="attack (altered)")
    ax[2].hist(y_score[y_true == 1], bins=60, alpha=.65, label="bona fide (real)")
    ax[2].axvline(0.5, ls="--", c="grey", lw=1)
    ax[2].set_xlabel("liveness score")
    ax[2].set_ylabel("count")
    ax[2].set_title("Score distribution")
    ax[2].legend()
    ax[2].set_yscale("log")
    ax[2].grid(alpha=.3)

    fig.suptitle("SFMPAS - PAD evaluation on held-out test set", fontsize=15)
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)
    log("Saved evaluation curves -> {}".format(path))


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="SFMPAS fingerprint PAD training")
    ap.add_argument("--epochs", type=int, default=50)
    ap.add_argument("--batch-size", type=int, default=32)
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--fakes-per-subfolder", type=int, default=6000)
    ap.add_argument("--test-size", type=float, default=0.20)
    ap.add_argument("--val-size", type=float, default=0.10,
                    help="fraction of the TRAIN portion used for early stopping")
    ap.add_argument("--split", choices=["stratified", "subject"], default="stratified")
    ap.add_argument("--patience", type=int, default=10)
    ap.add_argument("--monitor", default="val_auc",
                    help="early-stopping / checkpoint metric. Defaults to val_auc: "
                         "class weighting deliberately skews the operating point, so "
                         "val_loss and val_accuracy are threshold-distorted and are "
                         "poor model-selection criteria here. AUC is "
                         "threshold-independent.")
    ap.add_argument("--threshold", type=float, default=0.5)
    ap.add_argument("--augment", action="store_true")
    ap.add_argument("--real-weight-boost", type=float, default=1.0,
                    help="extra multiplier on the genuine-class weight to further "
                         "suppress BPCER")
    ap.add_argument("--limit", type=int, default=0, help="smoke-test subsample size")
    ap.add_argument("--tag", default="run")
    ap.add_argument("--no-gabor", dest="gabor", action="store_false",
                    help="ablation: skip Gabor enhancement (CLAHE + resize only), "
                         "to measure whether Gabor actually helps PAD")
    ap.add_argument("--out-subdir", default="",
                    help="write artefacts to outputs/<subdir> instead of outputs/, "
                         "so an ablation does not overwrite the main run")
    args = ap.parse_args()

    global OUT_DIR
    if args.out_subdir:
        OUT_DIR = os.path.join(OUT_DIR, args.out_subdir)
    os.makedirs(OUT_DIR, exist_ok=True)
    random.seed(SEED)
    np.random.seed(SEED)

    banner("SFMPAS | Fingerprint Presentation Attack Detection")
    log("Project root : {}".format(ROOT))
    log("Config       : {}".format(vars(args)))

    rng = random.Random(SEED)
    paths, labels, groups, subjects, alterations = build_inventory(
        args.fakes_per_subfolder, rng, args.limit or None)

    X = preprocess_cache(paths, args.tag if args.limit else "full", args.gabor)

    tr, va, te = make_split(labels, subjects, args.split,
                            args.test_size, args.val_size)

    # --- TensorFlow ---------------------------------------------------------
    import tensorflow as tf
    tf.keras.utils.set_random_seed(SEED)
    gpus = tf.config.list_physical_devices("GPU")
    log("TensorFlow {} | GPUs: {}".format(tf.__version__, gpus if gpus else "none (CPU)"))

    AUTO = tf.data.AUTOTUNE

    def make_ds(sel, training):
        ds = tf.data.Dataset.from_tensor_slices(
            (sel.astype(np.int64), labels[sel].astype(np.float32)))
        if training:
            ds = ds.shuffle(len(sel), seed=SEED, reshuffle_each_iteration=True)
        ds = ds.batch(args.batch_size)

        def fetch(ii, yy):
            def _read(a):
                return np.ascontiguousarray(X[a], dtype=np.uint8)
            img = tf.numpy_function(_read, [ii], tf.uint8)
            img.set_shape([None, IMG_SIZE, IMG_SIZE])
            img = tf.cast(img, tf.float32)          # keep [0,255] for MobileNetV3
            img = tf.repeat(img[..., None], 3, axis=-1)
            yy = tf.reshape(yy, [-1, 1])
            return img, yy

        return ds.map(fetch, num_parallel_calls=AUTO).prefetch(AUTO)

    ds_tr, ds_va, ds_te = make_ds(tr, True), make_ds(va, False), make_ds(te, False)

    model = build_model(tf, args.augment)

    # --- class weighting ----------------------------------------------------
    banner("STEP 7 | Class weighting (false-rejection protection)")
    cw = compute_class_weight("balanced", classes=np.array([0, 1]), y=labels[tr])
    class_weight = {0: float(cw[0]), 1: float(cw[1]) * args.real_weight_boost}
    log("class_weight = {{0 (attack): {:.4f}, 1 (genuine): {:.4f}}}".format(
        class_weight[0], class_weight[1]))
    log("Genuine samples are up-weighted so the loss penalises false rejection "
        "(BPCER) harder.")

    # --- optimiser ----------------------------------------------------------
    banner("STEP 8 | Compile: Adam + cosine decay")
    steps_per_epoch = math.ceil(len(tr) / args.batch_size)
    sched = tf.keras.optimizers.schedules.CosineDecay(
        initial_learning_rate=args.lr,
        decay_steps=steps_per_epoch * args.epochs,
        alpha=0.0)
    opt = tf.keras.optimizers.Adam(learning_rate=sched)
    model.compile(
        optimizer=opt,
        loss="binary_crossentropy",
        metrics=[tf.keras.metrics.BinaryAccuracy(name="accuracy"),
                 tf.keras.metrics.AUC(name="auc"),
                 tf.keras.metrics.Precision(name="precision"),
                 tf.keras.metrics.Recall(name="recall")],
    )
    log("Adam lr={} | cosine decay over {} steps ({} steps/epoch x {} epochs)".format(
        args.lr, steps_per_epoch * args.epochs, steps_per_epoch, args.epochs))

    lrs = []

    class LRLog(tf.keras.callbacks.Callback):
        def on_epoch_end(self, epoch, logs=None):
            lrs.append(float(sched(int(self.model.optimizer.iterations))))
            logs = logs or {}
            log("  epoch {:>3} | loss {:.4f} val_loss {:.4f} | acc {:.4f} "
                "val_acc {:.4f} | lr {:.2e}".format(
                    epoch + 1, logs.get("loss", 0), logs.get("val_loss", 0),
                    logs.get("accuracy", 0), logs.get("val_accuracy", 0), lrs[-1]))

    ckpt = os.path.join(OUT_DIR, "best_checkpoint.keras")
    mode = "min" if "loss" in args.monitor else "max"
    log("Model selection on '{}' (mode={}). Class weighting shifts the optimal "
        "threshold away from 0.5,".format(args.monitor, mode))
    log("so val_loss/val_accuracy are threshold-distorted; AUC ranks models on "
        "discriminative power alone.")
    callbacks = [
        tf.keras.callbacks.EarlyStopping(monitor=args.monitor, mode=mode,
                                         patience=args.patience,
                                         restore_best_weights=True, verbose=1),
        tf.keras.callbacks.ModelCheckpoint(ckpt, monitor=args.monitor, mode=mode,
                                           save_best_only=True, verbose=0),
        tf.keras.callbacks.CSVLogger(os.path.join(OUT_DIR, "training_log.csv")),
        LRLog(),
    ]

    banner("TRAINING | up to {} epochs".format(args.epochs))
    t0 = time.time()
    hist = model.fit(ds_tr, validation_data=ds_va, epochs=args.epochs,
                     class_weight=class_weight, callbacks=callbacks, verbose=1)
    wall = time.time() - t0
    log("Training finished in {:.1f} min ({} epochs)".format(
        wall / 60, len(hist.history["loss"])))

    # --- evaluate -----------------------------------------------------------
    banner("EVALUATION | held-out test set")
    y_score = model.predict(ds_te, verbose=1).ravel()
    y_true = labels[te]
    m = pad_metrics(y_true, y_score, groups[te], alterations[te], args.threshold)
    print_report(m, len(hist.history["loss"]), wall)

    # --- save ---------------------------------------------------------------
    banner("STEP 10 | Saving artefacts")
    curves = os.path.join(OUT_DIR, "training_curves.png")
    plot_curves(hist.history, lrs, curves)
    plot_eval(m, y_true, y_score, os.path.join(OUT_DIR, "evaluation_curves.png"))

    model_path = os.path.join(OUT_DIR, "sfmpas_mobilenetv3s_final.keras")
    model.save(model_path)
    log("Saved model -> {}".format(model_path))

    m_json = {k: v for k, v in m.items() if not k.startswith("_")}
    m_json["config"] = vars(args)
    m_json["epochs_run"] = len(hist.history["loss"])
    m_json["wall_clock_min"] = wall / 60
    m_json["class_weight"] = class_weight
    with open(os.path.join(OUT_DIR, "metrics.json"), "w") as f:
        json.dump(m_json, f, indent=2)
    np.savez_compressed(os.path.join(OUT_DIR, "test_scores.npz"),
                        y_true=y_true, y_score=y_score,
                        groups=groups[te], alterations=alterations[te])
    log("Saved metrics.json + test_scores.npz -> {}".format(OUT_DIR))
    banner("DONE")


if __name__ == "__main__":
    main()
