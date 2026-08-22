package com.sfmpas.app.data

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * FIDO2-style credential backed by the Android Keystore.
 *
 * A P-256 key pair is generated inside the keystore (hardware-backed / StrongBox
 * where the device offers it). The private key is non-exportable — it never
 * leaves the secure element — and is gated on biometric authentication, so a
 * signature can only be produced inside a successful `BiometricPrompt` ceremony
 * via a [javax.crypto.Cipher]-equivalent `CryptoObject`. That is the same
 * user-presence binding WebAuthn requires of an authenticator.
 *
 * This is deliberately *not* a full WebAuthn/FIDO2 implementation: there is no
 * relying party, no attestation conveyance, and no CTAP transport. It models the
 * on-device half of the ceremony, which is the part relevant to SFMPAS.
 */
object KeystoreManager {

    private const val TAG = "SFMPAS/Keystore"
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "sfmpas_fido2_key"
    const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

    /** Outcome of key creation, including whether biometric gating was applied. */
    data class KeyInfo(
        val alias: String,
        val publicKeyB64: String,
        val userAuthenticationRequired: Boolean,
        val strongBoxBacked: Boolean,
    ) {
        /** Short fingerprint of the public key, for display. */
        val publicKeyPreview: String
            get() = publicKeyB64.take(32) + "…"
    }

    private fun keyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    fun exists(): Boolean = runCatching { keyStore().containsAlias(KEY_ALIAS) }.getOrDefault(false)

    fun deleteKey() {
        runCatching { keyStore().deleteEntry(KEY_ALIAS) }
    }

    /**
     * Generates (or regenerates) the credential. Tries the strict configuration
     * first — biometric-gated and invalidated by new enrolments — and falls back
     * to an ungated key if the device rejects it, so the demo still runs. The
     * returned [KeyInfo.userAuthenticationRequired] reports which was used.
     */
    fun createKeyPair(): KeyInfo {
        deleteKey()
        return try {
            generate(requireUserAuth = true, strongBox = supportsStrongBox())
        } catch (t: Throwable) {
            Log.w(TAG, "Strict key generation failed; retrying without StrongBox", t)
            try {
                generate(requireUserAuth = true, strongBox = false)
            } catch (t2: Throwable) {
                Log.w(TAG, "Biometric-gated key unsupported; falling back to ungated", t2)
                generate(requireUserAuth = false, strongBox = false)
            }
        }
    }

    private fun supportsStrongBox(): Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P

    private fun generate(requireUserAuth: Boolean, strongBox: Boolean): KeyInfo {
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE
        )
        val spec = KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(requireUserAuth)
            .apply {
                if (requireUserAuth && Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    setInvalidatedByBiometricEnrollment(true)
                }
                if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    setIsStrongBoxBacked(true)
                }
            }
            .build()

        generator.initialize(spec)
        val pair = generator.generateKeyPair()
        return KeyInfo(
            alias = KEY_ALIAS,
            publicKeyB64 = Base64.encodeToString(pair.public.encoded, Base64.NO_WRAP),
            userAuthenticationRequired = requireUserAuth,
            strongBoxBacked = strongBox,
        )
    }

    fun publicKeyB64(): String? = runCatching {
        keyStore().getCertificate(KEY_ALIAS)?.publicKey?.encoded
            ?.let { Base64.encodeToString(it, Base64.NO_WRAP) }
    }.getOrNull()

    private fun privateKey(): PrivateKey? =
        runCatching { keyStore().getKey(KEY_ALIAS, null) as? PrivateKey }.getOrNull()

    /**
     * Builds a [Signature] initialised for signing, ready to be wrapped in a
     * `BiometricPrompt.CryptoObject`.
     *
     * @throws KeyPermanentlyInvalidatedException if biometrics were re-enrolled
     *   since the key was created — the caller should re-register.
     */
    fun signatureForSigning(): Signature? {
        val key = privateKey() ?: return null
        val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
        signature.initSign(key)   // throws if the key was invalidated
        return signature
    }

    /** Canonical bytes signed for a payment assertion. */
    fun challengeFor(recipient: String, amountNaira: Long, timestampMillis: Long): ByteArray =
        "SFMPAS|$recipient|$amountNaira|$timestampMillis".toByteArray()

    fun encodeSignature(raw: ByteArray): String =
        Base64.encodeToString(raw, Base64.NO_WRAP)
}
