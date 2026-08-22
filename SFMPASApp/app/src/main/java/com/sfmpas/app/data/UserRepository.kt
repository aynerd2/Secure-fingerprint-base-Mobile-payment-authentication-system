package com.sfmpas.app.data

import android.content.Context
import com.sfmpas.app.model.Occupation
import com.sfmpas.app.model.UserProfile
import java.util.UUID

/** Persists the registered account holder in (encrypted) SharedPreferences. */
class UserRepository(context: Context) {

    private val prefs = SecurePrefs.open(context.applicationContext, PREFS_NAME)

    fun isRegistered(): Boolean = prefs.contains(KEY_NAME)

    fun save(profile: UserProfile) {
        prefs.edit()
            .putString(KEY_USER_ID, profile.userId)
            .putString(KEY_NAME, profile.fullName)
            .putString(KEY_PHONE, profile.phoneNumber)
            .putString(KEY_OCCUPATION, profile.occupation.name)
            .putLong(KEY_REGISTERED_AT, profile.registeredAtMillis)
            .putString(KEY_TIER, profile.accountTier)
            .putLong(KEY_BALANCE, profile.balanceNaira)
            .apply()
    }

    fun load(): UserProfile? {
        val name = prefs.getString(KEY_NAME, null) ?: return null
        return UserProfile(
            userId = userId(),
            fullName = name,
            phoneNumber = prefs.getString(KEY_PHONE, "").orEmpty(),
            occupation = Occupation.fromName(prefs.getString(KEY_OCCUPATION, null)),
            registeredAtMillis = prefs.getLong(KEY_REGISTERED_AT, 0L),
            accountTier = prefs.getString(KEY_TIER, "Tier 1").orEmpty(),
            balanceNaira = prefs.getLong(KEY_BALANCE, DEFAULT_BALANCE),
        )
    }

    /**
     * Mock ledger movement — the balance is local demo state, not a real account.
     *
     * Returns `false` and leaves the balance untouched when the debit would
     * overdraw. Callers must treat a `false` return as a failed payment: silently
     * clamping to zero would let an unaffordable transaction report success.
     */
    fun debit(amountNaira: Long): Boolean {
        val current = balance()
        if (amountNaira <= 0L || amountNaira > current) return false
        prefs.edit().putLong(KEY_BALANCE, current - amountNaira).apply()
        return true
    }

    fun balance(): Long = prefs.getLong(KEY_BALANCE, DEFAULT_BALANCE)

    fun canAfford(amountNaira: Long): Boolean =
        amountNaira > 0L && amountNaira <= balance()

    /**
     * Restores the demo float. Exposed for the user study so a session can be
     * repeated without clearing app data (which would also destroy the
     * registration and the Keystore credential).
     */
    fun resetBalance(): Long {
        prefs.edit().putLong(KEY_BALANCE, DEFAULT_BALANCE).apply()
        return DEFAULT_BALANCE
    }

    /**
     * Stable user id, minted once and reused for every backend call. Generated
     * locally rather than issued by the server so registration still works
     * offline — the id is just a handle, it carries no authority on its own.
     */
    fun userId(): String {
        prefs.getString(KEY_USER_ID, null)?.let { return it }
        val fresh = "sfmpas-" + UUID.randomUUID().toString().take(12)
        prefs.edit().putString(KEY_USER_ID, fresh).apply()
        return fresh
    }

    /** True once /register has been accepted by the backend. */
    fun isBackendSynced(): Boolean = prefs.getBoolean(KEY_BACKEND_SYNCED, false)

    fun setBackendSynced(synced: Boolean) =
        prefs.edit().putBoolean(KEY_BACKEND_SYNCED, synced).apply()

    fun clear() = prefs.edit().clear().apply()

    companion object {
        private const val PREFS_NAME = "sfmpas_user"
        private const val KEY_NAME = "full_name"
        private const val KEY_PHONE = "phone_number"
        private const val KEY_OCCUPATION = "occupation"
        private const val KEY_REGISTERED_AT = "registered_at"
        private const val KEY_TIER = "account_tier"
        private const val KEY_BALANCE = "balance"
        private const val KEY_USER_ID = "user_id"
        private const val KEY_BACKEND_SYNCED = "backend_synced"
        const val DEFAULT_BALANCE = 5_000_000L
    }
}
