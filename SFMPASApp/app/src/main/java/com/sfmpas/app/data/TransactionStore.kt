package com.sfmpas.app.data

import android.content.Context
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.sfmpas.app.model.Transaction

/** Local, newest-first transaction log backed by (encrypted) SharedPreferences. */
class TransactionStore(context: Context) {

    private val prefs = SecurePrefs.open(context.applicationContext, PREFS_NAME)
    private val gson = Gson()

    fun all(): List<Transaction> {
        val raw = prefs.getString(KEY_LOG, null) ?: return emptyList()
        return runCatching {
            val type = object : TypeToken<List<Transaction>>() {}.type
            gson.fromJson<List<Transaction>>(raw, type) ?: emptyList()
        }.getOrDefault(emptyList())
    }

    fun add(transaction: Transaction) {
        val updated = (listOf(transaction) + all()).take(MAX_ENTRIES)
        prefs.edit().putString(KEY_LOG, gson.toJson(updated)).apply()
    }

    fun clear() = prefs.edit().remove(KEY_LOG).apply()

    companion object {
        private const val PREFS_NAME = "sfmpas_transactions"
        private const val KEY_LOG = "log"
        private const val MAX_ENTRIES = 100
    }
}
