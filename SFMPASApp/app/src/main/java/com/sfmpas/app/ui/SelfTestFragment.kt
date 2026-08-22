package com.sfmpas.app.ui

import android.graphics.Bitmap
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.sfmpas.app.PadInferenceEngine
import com.sfmpas.app.R
import com.sfmpas.app.databinding.FragmentSelfTestBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import kotlin.math.abs

/**
 * Diagnostic screen retained from the porting phase.
 *
 * Separates the two failure modes that are easy to confuse:
 *   1. PREPROCESSING parity — does the Kotlin CLAHE + bicubic chain reproduce
 *      what OpenCV produced during training?
 *   2. MODEL parity — given byte-identical input, does the on-device TFLite
 *      interpreter reproduce the desktop score?
 */
class SelfTestFragment : Fragment() {

    private var _binding: FragmentSelfTestBinding? = null
    private val binding get() = _binding!!
    private var engine: PadInferenceEngine? = null

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentSelfTestBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        binding.statusText.text = getString(R.string.status_idle)
        binding.runButton.setOnClickListener { run() }
    }

    override fun onDestroyView() {
        engine?.close()
        engine = null
        _binding = null
        super.onDestroyView()
    }

    private fun run() {
        binding.runButton.isEnabled = false
        binding.statusText.text = "Running self-test…"
        viewLifecycleOwner.lifecycleScope.launch {
            val report = withContext(Dispatchers.Default) { selfTest() }
            if (!isAdded || _binding == null) return@launch
            binding.statusText.text = report
            binding.runButton.isEnabled = true
        }
    }

    private fun selfTest(): String = buildString {
        val started = System.currentTimeMillis()
        try {
            val eng = engine
                ?: PadInferenceEngine(requireContext()).also { engine = it }
            appendLine("model : ${PadInferenceEngine.MODEL_ASSET}")

            val assets = requireContext().assets
            val meta = JSONObject(
                assets.open("selftest.json").bufferedReader().use { it.readText() }
            )
            val samples = meta.getJSONArray("samples")
            appendLine("cases : ${samples.length()}")
            appendLine()

            var worstPixelDiff = 0
            var worstScoreDiff = 0.0

            for (i in 0 until samples.length()) {
                val s = samples.getJSONObject(i)
                val w = s.getInt("width")
                val h = s.getInt("height")
                val expectedScore = s.getDouble("expected_score")

                val raw = assets.open(s.getString("input_file")).use { it.readBytes() }
                val expected = assets.open(s.getString("expected_file")).use { it.readBytes() }

                val referencePlane = IntArray(expected.size) { expected[it].toInt() and 0xFF }
                val scoreOnReference = eng.scorePreprocessed(referencePlane)

                val bitmap = grayToBitmap(raw, w, h)
                val ourPlane = eng.preprocess(bitmap)
                bitmap.recycle()

                var maxDiff = 0
                var diffCount = 0
                var sumDiff = 0L
                for (p in ourPlane.indices) {
                    val d = abs(ourPlane[p] - referencePlane[p])
                    if (d != 0) diffCount++
                    if (d > maxDiff) maxDiff = d
                    sumDiff += d
                }
                val scoreOnOurs = eng.scorePreprocessed(ourPlane)

                worstPixelDiff = maxOf(worstPixelDiff, maxDiff)
                worstScoreDiff = maxOf(
                    worstScoreDiff,
                    abs(scoreOnOurs - expectedScore.toFloat()).toDouble()
                )

                appendLine("[${s.getString("label")}]  ${s.getString("source")}")
                appendLine("  expected score      : %.6f".format(expectedScore))
                appendLine("  score (python prep) : %.6f".format(scoreOnReference))
                appendLine("  score (kotlin prep) : %.6f".format(scoreOnOurs))
                appendLine(
                    "  pixel diff vs opencv: max=%d  differing=%d/%d (%.2f%%)  mean=%.3f"
                        .format(
                            maxDiff, diffCount, ourPlane.size,
                            100.0 * diffCount / ourPlane.size,
                            sumDiff.toDouble() / ourPlane.size,
                        )
                )
                appendLine()
            }

            appendLine("─".repeat(34))
            appendLine("worst pixel delta : $worstPixelDiff / 255")
            appendLine("worst score delta : %.6f".format(worstScoreDiff))
            appendLine("elapsed           : ${System.currentTimeMillis() - started} ms")
            appendLine()
            appendLine(
                if (worstScoreDiff < 0.01) {
                    "PASS — preprocessing and model agree with the training pipeline."
                } else {
                    "REVIEW — scores diverge from the desktop reference; check that " +
                        "CLAHE/bicubic match OpenCV, or switch to OpenCV for Android."
                }
            )
        } catch (t: Throwable) {
            appendLine("FAILED: ${t::class.java.simpleName}: ${t.message}")
        }
    }

    private fun grayToBitmap(raw: ByteArray, w: Int, h: Int): Bitmap {
        val packed = IntArray(w * h)
        for (i in packed.indices) {
            val v = raw[i].toInt() and 0xFF
            packed[i] = (0xFF shl 24) or (v shl 16) or (v shl 8) or v
        }
        return Bitmap.createBitmap(packed, w, h, Bitmap.Config.ARGB_8888)
    }
}
