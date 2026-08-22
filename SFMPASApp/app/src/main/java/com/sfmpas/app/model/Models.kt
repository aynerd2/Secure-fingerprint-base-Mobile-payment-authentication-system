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
    /**
     * The `transaction_id` the backend assigned, when the payment was verified
     * server-side. Null means the transaction was settled on device only —
     * either the backend was unreachable, or it rejected the assertion before a
     * server record existed. Kept alongside the local id so a row in this log
     * can be reconciled against the server's audit trail.
     */
    val serverTransactionId: String? = null,
) {
    /** True when this record was confirmed by the backend rather than locally. */
    val isServerVerified: Boolean get() = !serverTransactionId.isNullOrBlank()

    fun formattedTime(): String =
        SimpleDateFormat("dd MMM yyyy, HH:mm", Locale.UK).format(Date(timestampMillis))
}

/** Formats a whole-Naira value as e.g. `₦250,000`. */
fun formatNaira(amount: Long): String =
    "₦" + String.format(Locale.UK, "%,d", amount)
