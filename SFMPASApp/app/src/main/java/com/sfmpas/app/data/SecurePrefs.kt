package com.sfmpas.app.data

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Provides an [EncryptedSharedPreferences] instance, falling back to plain
 * [SharedPreferences] if the keystore-backed store cannot be created.
 *
 * The fallback exists because `security-crypto` is still an alpha artifact and
 * is known to fail on a handful of devices with a damaged keystore. Failing
 * open to plain preferences keeps the demo usable; a production build should
 * fail closed instead, and the flag is surfaced so the UI can say which store
 * is in use.
 */
object SecurePrefs {

    private const val TAG = "SFMPAS/SecurePrefs"

    @Volatile
    var usingEncryptedStore: Boolean = true
        private set

    fun open(context: Context, name: String): SharedPreferences {
        return try {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            EncryptedSharedPreferences.create(
                context,
                name,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
            ).also { usingEncryptedStore = true }
        } catch (t: Throwable) {
            Log.w(TAG, "EncryptedSharedPreferences unavailable; using plain store", t)
            usingEncryptedStore = false
            context.getSharedPreferences("${name}_plain", Context.MODE_PRIVATE)
        }
    }
}
