package com.bankvault.security

import android.content.Context
import android.util.Base64

/**
 * SharedPreferences whose values are AES-GCM encrypted with the Keystore DATA key.
 * Keys (names) are not secret. Values that fail to decrypt are treated as absent.
 */
class SecurePrefs(context: Context, name: String = "bv_secure") {
    private val sp = context.getSharedPreferences(name, Context.MODE_PRIVATE)

    fun putString(key: String, value: String?) {
        val e = sp.edit()
        if (value == null) e.remove(key)
        else e.putString(key, Base64.encodeToString(KeystoreManager.encrypt(value.toByteArray()), Base64.NO_WRAP))
        e.commit() // synchronous: security state must be on disk before we continue
    }

    fun getString(key: String): String? = sp.getString(key, null)?.let {
        try { String(KeystoreManager.decrypt(Base64.decode(it, Base64.NO_WRAP))) } catch (_: Exception) { null }
    }

    fun putLong(key: String, v: Long) = putString(key, v.toString())
    fun getLong(key: String, def: Long = 0L) = getString(key)?.toLongOrNull() ?: def
    fun putBool(key: String, v: Boolean) = putString(key, v.toString())
    fun getBool(key: String, def: Boolean = false) = getString(key)?.toBooleanStrictOrNull() ?: def
    fun contains(key: String) = sp.contains(key)
    fun clear() { sp.edit().clear().commit() }
}
