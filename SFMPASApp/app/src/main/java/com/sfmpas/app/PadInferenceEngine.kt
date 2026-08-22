package com.sfmpas.app

import android.content.Context
import android.graphics.Bitmap
import org.tensorflow.lite.Interpreter
import java.io.Closeable
import java.io.FileInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.MappedByteBuffer
import java.nio.channels.FileChannel
import java.util.Arrays
import kotlin.math.floor
import kotlin.math.roundToInt

/**
 * Runs the SFMPAS fingerprint presentation-attack-detection (liveness) model.
 *
 * The preprocessing here must match the training pipeline **exactly**, or the
 * scores are meaningless. Training did, in order:
 *
 *   1. read the print as 8-bit grayscale
 *   2. CLAHE, clipLimit = 2.0, tile grid 8x8      (OpenCV `cv2.createCLAHE`)
 *   3. resize to 224x224, bicubic                 (OpenCV `cv2.INTER_CUBIC`)
 *   4. replicate the single channel to 3 channels
 *   5. feed as float32 in the range 0..255        (NOT divided by 255)
 *
 * Step 5 matters: the exported graph carries MobileNetV3's own rescaling layer
 * as its first op, so it expects raw 0..255 values. Normalising here would
 * rescale twice and destroy accuracy.
 *
 * There is deliberately **no Gabor filter**. An ablation showed Gabor ridge
 * enhancement made detection ~19x worse (ACER 9.87% -> 0.51%), because it
 * emphasises ridge *continuity* while alterations are ridge *discontinuities*.
 * The input tensor is still named `gabor_input`, which is a historical artefact
 * of the original architecture, not an instruction to apply one.
 *
 * ### A note on CLAHE and bicubic parity
 * Android ships neither CLAHE nor a bicubic resampler, and
 * `tensorflow-lite-support`'s `ResizeOp` supports only bilinear and
 * nearest-neighbour. Both algorithms below are therefore reimplemented against
 * OpenCV's own source (`modules/imgproc/src/clahe.cpp` and `resize.cpp`),
 * including OpenCV's BORDER_REFLECT_101 tile padding, its integer clip-limit
 * derivation, and its A = -0.75 cubic kernel. They agree with OpenCV closely but
 * are not guaranteed bit-identical at image borders. Run `selfTest` on device to
 * measure the actual agreement against a Python-generated reference. If you need
 * a hard guarantee, add OpenCV for Android (`org.opencv:opencv:4.9.0` or newer)
 * and swap [applyClahe]/[resizeBicubic] for `Imgproc.createCLAHE` and
 * `Imgproc.resize(..., Imgproc.INTER_CUBIC)`.
 *
 * Not thread-safe: a TFLite [Interpreter] must be driven from one thread at a
 * time. Either confine an instance to a single worker thread or guard [score].
 */
class PadInferenceEngine(
    context: Context,
    numThreads: Int = DEFAULT_THREADS,
) : Closeable {

    companion object {
        const val MODEL_ASSET = "sfmpas_pad.tflite"

        /** Model input is [1, 224, 224, 3]. */
        const val INPUT_SIZE = 224
        const val INPUT_CHANNELS = 3

        /** >= this score means genuine (bona fide); below means attack. */
        const val DEFAULT_THRESHOLD = 0.5f

        /** Matches `cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))`. */
        const val CLAHE_CLIP_LIMIT = 2.0
        const val CLAHE_TILES_X = 8
        const val CLAHE_TILES_Y = 8

        private const val HIST_SIZE = 256
        private const val DEFAULT_THREADS = 4
        private const val CUBIC_A = -0.75f
        private const val BYTES_PER_FLOAT = 4
    }

    private val interpreter: Interpreter
    private val inputBuffer: ByteBuffer =
        ByteBuffer
            .allocateDirect(INPUT_SIZE * INPUT_SIZE * INPUT_CHANNELS * BYTES_PER_FLOAT)
            .order(ByteOrder.nativeOrder())
    private val outputBuffer = Array(1) { FloatArray(1) }

    init {
        val options = Interpreter.Options().apply { setNumThreads(numThreads) }
        interpreter = Interpreter(loadModelFile(context), options)
    }

    // ---------------------------------------------------------------- public

    /**
     * Scores a fingerprint image.
     *
     * @param bitmap the captured print. Colour bitmaps are converted to
     *   grayscale using OpenCV's BGR->GRAY weights; an already-grayscale image
     *   passes through untouched.
     * @return liveness score in `[0, 1]`; `>= 0.5` means genuine.
     */
    fun score(bitmap: Bitmap): Float {
        val pixels = preprocess(bitmap)
        return scorePreprocessed(pixels)
    }

    /**
     * Runs the model on an already-preprocessed 224x224 grayscale plane
     * (values 0..255, row-major). Exposed so `selfTest` can isolate model
     * behaviour from preprocessing behaviour.
     */
    fun scorePreprocessed(plane: IntArray): Float {
        require(plane.size == (INPUT_SIZE * INPUT_SIZE)) {
            "expected ${INPUT_SIZE * INPUT_SIZE} pixels, got ${plane.size}"
        }
        inputBuffer.rewind()
        for (i in plane.indices) {
            // float32 in 0..255 — deliberately NOT divided by 255
            val v = plane[i].toFloat()
            inputBuffer.putFloat(v)   // R
            inputBuffer.putFloat(v)   // G  (single channel replicated)
            inputBuffer.putFloat(v)   // B
        }
        inputBuffer.rewind()
        interpreter.run(inputBuffer, outputBuffer)
        return outputBuffer[0][0]
    }

    /**
     * Full preprocessing chain: grayscale -> CLAHE -> bicubic 224x224.
     * Returns a row-major plane of 224*224 values in 0..255.
     */
    fun preprocess(bitmap: Bitmap): IntArray {
        val w = bitmap.width
        val h = bitmap.height
        require(w > 0 && h > 0) { "empty bitmap" }
        val gray = bitmapToGray(bitmap, w, h)
        val equalised = applyClahe(gray, w, h)
        return resizeBicubic(equalised, w, h, INPUT_SIZE, INPUT_SIZE)
    }

    override fun close() = interpreter.close()

    // ------------------------------------------------------------ model load

    private fun loadModelFile(context: Context): MappedByteBuffer {
        // Memory-maps the asset directly, which requires it to be STORED rather
        // than DEFLATED in the APK. `androidResources { noCompress += "tflite" }`
        // in app/build.gradle.kts guarantees that.
        context.assets.openFd(MODEL_ASSET).use { afd ->
            FileInputStream(afd.fileDescriptor).use { stream ->
                return stream.channel.map(
                    FileChannel.MapMode.READ_ONLY,
                    afd.startOffset,
                    afd.declaredLength
                )
            }
        }
    }

    // ---------------------------------------------------------- preprocessing

    /** Matches `cv2.imread(..., IMREAD_GRAYSCALE)` for colour input. */
    private fun bitmapToGray(bitmap: Bitmap, w: Int, h: Int): IntArray {
        val argb = if (bitmap.config == Bitmap.Config.ARGB_8888) {
            bitmap
        } else {
            bitmap.copy(Bitmap.Config.ARGB_8888, false)
        }
        val packed = IntArray(w * h)
        argb.getPixels(packed, 0, w, 0, 0, w, h)
        if (argb !== bitmap) argb.recycle()

        val gray = IntArray(w * h)
        for (i in packed.indices) {
            val p = packed[i]
            val r = (p shr 16) and 0xFF
            val g = (p shr 8) and 0xFF
            val b = p and 0xFF
            gray[i] = if (r == g && g == b) {
                r                                  // already grayscale — exact
            } else {
                // OpenCV's fixed-point BGR->GRAY: 0.299R + 0.587G + 0.114B
                ((r * 4899 + g * 9617 + b * 1868 + 8192) shr 14).coerceIn(0, 255)
            }
        }
        return gray
    }

    /**
     * Contrast Limited Adaptive Histogram Equalisation, following OpenCV's
     * `clahe.cpp`: reflect-101 pad so the tile grid divides evenly, per-tile
     * clipped histogram with uniform redistribution of the clipped mass, then
     * bilinear interpolation between the four neighbouring tile LUTs.
     */
    private fun applyClahe(gray: IntArray, w: Int, h: Int): IntArray {
        val tilesX = CLAHE_TILES_X
        val tilesY = CLAHE_TILES_Y

        // OpenCV pads with BORDER_REFLECT_101 when the grid does not divide
        // the image evenly, and builds the LUTs from the padded image.
        val padW = if (w % tilesX == 0) w else w + (tilesX - w % tilesX)
        val padH = if (h % tilesY == 0) h else h + (tilesY - h % tilesY)
        val lutSrc = if (padW == w && padH == h) gray
                     else reflect101(gray, w, h, padW, padH)

        val tileW = padW / tilesX
        val tileH = padH / tilesY
        val tileArea = tileW * tileH
        val lutScale = 255.0f / tileArea

        // OpenCV truncates to int and floors at 1 — with small tiles this often
        // lands on 1, which is aggressive but is exactly what training used.
        val clipLimit = maxOf((CLAHE_CLIP_LIMIT * tileArea / HIST_SIZE).toInt(), 1)

        val luts = Array(tilesX * tilesY) { IntArray(HIST_SIZE) }
        val hist = IntArray(HIST_SIZE)

        for (ty in 0 until tilesY) {
            for (tx in 0 until tilesX) {
                Arrays.fill(hist, 0)
                val y0 = ty * tileH
                val x0 = tx * tileW
                for (yy in y0 until y0 + tileH) {
                    val row = yy * padW
                    for (xx in x0 until x0 + tileW) hist[lutSrc[row + xx]]++
                }

                var clipped = 0
                for (i in 0 until HIST_SIZE) {
                    if (hist[i] > clipLimit) {
                        clipped += hist[i] - clipLimit
                        hist[i] = clipLimit
                    }
                }
                val redistBatch = clipped / HIST_SIZE
                var residual = clipped - redistBatch * HIST_SIZE
                if (redistBatch != 0) {
                    for (i in 0 until HIST_SIZE) hist[i] += redistBatch
                }
                if (residual != 0) {
                    val step = maxOf(HIST_SIZE / residual, 1)
                    var i = 0
                    while (i < HIST_SIZE && residual > 0) {
                        hist[i]++
                        residual--
                        i += step
                    }
                }

                var sum = 0
                val plane = luts[ty * tilesX + tx]
                for (i in 0 until HIST_SIZE) {
                    sum += hist[i]
                    plane[i] = (sum * lutScale).roundToInt().coerceIn(0, 255)
                }
            }
        }

        // Interpolate over the ORIGINAL (unpadded) image.
        val out = IntArray(w * h)
        val invTileW = 1.0f / tileW
        val invTileH = 1.0f / tileH

        for (y in 0 until h) {
            val tyf = y * invTileH - 0.5f
            val tyFloor = floor(tyf).toInt()
            val ya = tyf - tyFloor
            val ty1 = tyFloor.coerceAtLeast(0)
            val ty2 = (tyFloor + 1).coerceAtMost(tilesY - 1)
            val rowBase = y * w

            for (x in 0 until w) {
                val txf = x * invTileW - 0.5f
                val txFloor = floor(txf).toInt()
                val xa = txf - txFloor
                val tx1 = txFloor.coerceAtLeast(0)
                val tx2 = (txFloor + 1).coerceAtMost(tilesX - 1)

                val v = gray[rowBase + x]
                val res =
                    luts[ty1 * tilesX + tx1][v] * ((1f - xa) * (1f - ya)) +
                    luts[ty1 * tilesX + tx2][v] * (xa * (1f - ya)) +
                    luts[ty2 * tilesX + tx1][v] * ((1f - xa) * ya) +
                    luts[ty2 * tilesX + tx2][v] * (xa * ya)
                out[rowBase + x] = res.roundToInt().coerceIn(0, 255)
            }
        }
        return out
    }

    /** BORDER_REFLECT_101 padding on the bottom/right edges only. */
    private fun reflect101(src: IntArray, w: Int, h: Int, padW: Int, padH: Int): IntArray {
        val out = IntArray(padW * padH)
        for (y in 0 until padH) {
            val sy = (if (y < h) y else 2 * (h - 1) - y).coerceIn(0, h - 1)
            for (x in 0 until padW) {
                val sx = (if (x < w) x else 2 * (w - 1) - x).coerceIn(0, w - 1)
                out[y * padW + x] = src[sy * w + sx]
            }
        }
        return out
    }

    /**
     * Bicubic resample equivalent to `cv2.resize(..., interpolation=INTER_CUBIC)`:
     * a 4x4 support with OpenCV's A = -0.75 kernel, centre-aligned coordinate
     * mapping, and edge indices clamped (replicate).
     */
    private fun resizeBicubic(
        src: IntArray, sw: Int, sh: Int, dw: Int, dh: Int
    ): IntArray {
        val scaleX = sw.toFloat() / dw
        val scaleY = sh.toFloat() / dh

        val xIdx = IntArray(dw * 4)
        val xCoef = FloatArray(dw * 4)
        for (dx in 0 until dw) {
            var fx = (dx + 0.5f) * scaleX - 0.5f
            val sx = floor(fx).toInt()
            fx -= sx
            cubicCoefficients(fx, xCoef, dx * 4)
            for (k in 0 until 4) xIdx[dx * 4 + k] = (sx - 1 + k).coerceIn(0, sw - 1)
        }

        val yIdx = IntArray(dh * 4)
        val yCoef = FloatArray(dh * 4)
        for (dy in 0 until dh) {
            var fy = (dy + 0.5f) * scaleY - 0.5f
            val sy = floor(fy).toInt()
            fy -= sy
            cubicCoefficients(fy, yCoef, dy * 4)
            for (k in 0 until 4) yIdx[dy * 4 + k] = (sy - 1 + k).coerceIn(0, sh - 1)
        }

        val out = IntArray(dw * dh)
        for (dy in 0 until dh) {
            val yo = dy * 4
            for (dx in 0 until dw) {
                val xo = dx * 4
                var acc = 0f
                for (ky in 0 until 4) {
                    val rowStart = yIdx[yo + ky] * sw
                    var rowAcc = 0f
                    for (kx in 0 until 4) {
                        rowAcc += src[rowStart + xIdx[xo + kx]] * xCoef[xo + kx]
                    }
                    acc += rowAcc * yCoef[yo + ky]
                }
                out[dy * dw + dx] = acc.roundToInt().coerceIn(0, 255)
            }
        }
        return out
    }

    /** OpenCV's `interpolateCubic` with A = -0.75. */
    private fun cubicCoefficients(x: Float, dst: FloatArray, offset: Int) {
        val a = CUBIC_A
        dst[offset] = ((a * (x + 1) - 5 * a) * (x + 1) + 8 * a) * (x + 1) - 4 * a
        dst[offset + 1] = ((a + 2) * x - (a + 3)) * x * x + 1
        dst[offset + 2] = ((a + 2) * (1 - x) - (a + 3)) * (1 - x) * (1 - x) + 1
        dst[offset + 3] = 1f - dst[offset] - dst[offset + 1] - dst[offset + 2]
    }
}
