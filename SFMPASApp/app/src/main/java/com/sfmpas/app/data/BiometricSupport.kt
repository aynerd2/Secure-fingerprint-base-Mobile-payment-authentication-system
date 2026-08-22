package com.sfmpas.app.data

import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt

/**
 * Wraps biometric availability checks.
 *
 * Note on terminology: an app **cannot enrol** a fingerprint. Enrolment happens
 * only in system Settings; `BiometricPrompt` can merely *verify* an already
 * enrolled finger. "Register Fingerprint" in this app therefore means: confirm a
 * finger is enrolled, verify the user owns it, and bind a Keystore credential to
 * it. If nothing is enrolled we hand the user off to Settings via [enrolIntent].
 */
object BiometricSupport {

    enum class Availability { READY, NONE_ENROLLED, NO_HARDWARE, UNAVAILABLE, UNKNOWN }

    fun availability(context: Context): Availability {
        val manager = BiometricManager.from(context)
        return when (manager.canAuthenticate(BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS -> Availability.READY
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> Availability.NONE_ENROLLED
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> Availability.NO_HARDWARE
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> Availability.UNAVAILABLE
            else -> Availability.UNKNOWN
        }
    }

    fun describe(availability: Availability): String = when (availability) {
        Availability.READY -> "Fingerprint sensor ready."
        Availability.NONE_ENROLLED ->
            "No fingerprint enrolled. Add one in Settings, then return here."
        Availability.NO_HARDWARE -> "This device has no fingerprint sensor."
        Availability.UNAVAILABLE -> "Fingerprint sensor temporarily unavailable."
        Availability.UNKNOWN -> "Fingerprint status unknown on this device."
    }

    /** Sends the user to system biometric enrolment. */
    fun enrolIntent(): Intent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        Intent(Settings.ACTION_BIOMETRIC_ENROLL).apply {
            putExtra(Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED, BIOMETRIC_STRONG)
        }
    } else {
        Intent(Settings.ACTION_SECURITY_SETTINGS)
    }

    /** Standard biometric-only prompt (has its own cancel button). */
    fun prompt(title: String, subtitle: String, description: String? = null):
        BiometricPrompt.PromptInfo =
        BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .apply { description?.let { setDescription(it) } }
            .setAllowedAuthenticators(BIOMETRIC_STRONG)
            .setNegativeButtonText("Cancel")
            .setConfirmationRequired(true)
            .build()

    /**
     * Prompt for Tier 3 enhanced verification, which also accepts the device
     * PIN/pattern/password. A negative button must NOT be set when
     * DEVICE_CREDENTIAL is allowed — the framework supplies its own.
     */
    fun enhancedPrompt(title: String, subtitle: String, description: String):
        BiometricPrompt.PromptInfo =
        BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setDescription(description)
            .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
            .setConfirmationRequired(true)
            .build()
}
