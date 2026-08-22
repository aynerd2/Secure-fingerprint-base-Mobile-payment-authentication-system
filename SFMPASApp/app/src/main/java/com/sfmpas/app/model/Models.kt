package com.sfmpas.app.model

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Occupation captured at registration. */
enum class Occupation(val displayName: String) {
    GENERAL_USER("General User"),
    MANUAL_LABOUR_WORKER("Manual Labour Worker");

    companion object {
        fun fromName(raw: String?): Occupation =
            entries.firstOrNull { it.name == raw } ?: GENERAL_USER
    }
}

/** Locally stored account holder. No biometric data is ever persisted here. */
data class UserProfile(
    /** Stable identifier for this enrolment; the backend's primary key. */
    val userId: String,
    val fullName: String,
    val phoneNumber: String,
    val occupation: Occupation,
    val registeredAtMillis: Long,
    val accountTier: String = "Tier 1",
    val balanceNaira: Long = 5_000_000L,
) {
    val firstName: String get() = fullName.trim().substringBefore(' ').ifBlank { fullName }
}

/** A completed authentication attempt, approved or rejected. */
data class Transaction(
    val id: String,
    val recipient: String,
    val amountNaira: Long,
    val tierName: String,
    val timestampMillis: Long,
    val approved: Boolean,
    val livenessScore: Float,
    val livenessEnforced: Boolean,
    val reason: String,
    val signaturePreview: String,
) {
    fun formattedTime(): String =
        SimpleDateFormat("dd MMM yyyy, HH:mm", Locale.UK).format(Date(timestampMillis))
}

/** Formats a whole-Naira value as e.g. `₦250,000`. */
fun formatNaira(amount: Long): String =
    "₦" + String.format(Locale.UK, "%,d", amount)
