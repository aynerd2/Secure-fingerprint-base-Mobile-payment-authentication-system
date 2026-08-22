package com.sfmpas.app.data

import android.content.Context
import android.graphics.Bitmap
import org.json.JSONObject

/**
 * Loads the bundled reference fingerprints used to drive the PAD check.
 *
 * These are the same fixtures the self-test uses, taken straight from the
 * SOCOFing evaluation set: index 0 is a genuine print, index 1 is the same
 * finger with a Z-cut alteration (the attack class the model finds hardest).
 *
 * They stand in for a live capture because **Android exposes no API for reading
 * a raw fingerprint image** — `BiometricPrompt` returns only success or failure.
 * A production SFMPAS deployment would source this bitmap from an external
 * scanner SDK; everything downstream of [load] is unchanged by that swap.
 */
object ReferencePrints {

    const val GENUINE = 0
    const val ATTACK = 1

    data class Reference(
        val index: Int,
        val label: String,
        val source: String,
        val bitmap: Bitmap,
        val expectedScore: Float,
    )

    fun load(context: Context, index: Int): Reference {
        val meta = JSONObject(
            context.assets.open("selftest.json").bufferedReader().use { it.readText() }
        )
        val samples = meta.getJSONArray("samples")
        val entry = (0 until samples.length())
            .map { samples.getJSONObject(it) }
            .firstOrNull { it.getInt("index") == index }
            ?: error("no reference print with index $index")

        val width = entry.getInt("width")
        val height = entry.getInt("height")
        val raw = context.assets.open(entry.getString("input_file")).use { it.readBytes() }

        val packed = IntArray(width * height)
        for (i in packed.indices) {
            val v = raw[i].toInt() and 0xFF
            packed[i] = (0xFF shl 24) or (v shl 16) or (v shl 8) or v
        }

        return Reference(
            index = index,
            label = entry.getString("label"),
            source = entry.getString("source"),
            bitmap = Bitmap.createBitmap(packed, width, height, Bitmap.Config.ARGB_8888),
            expectedScore = entry.getDouble("expected_score").toFloat(),
        )
    }
}
