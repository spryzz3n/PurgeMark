package com.purgemark.mobile.platform

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import com.purgemark.mobile.core.Challenge
import com.purgemark.mobile.core.Record
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Generates a fresh ECDSA P-256 key in the Android Keystore with the
 * challenge baked into its attestation certificate. A new alias per record:
 * the key is meant to be destroyed by the factory reset that follows.
 */
class KeystoreAttestation private constructor(
    private val privateKey: PrivateKey,
    override val chainDer: List<ByteArray>,
    override val securityLevel: Record.SecurityLevel,
) : Record.AttestedKey {

    override fun sign(message: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(privateKey)
            update(message)
            sign()
        }

    companion object {
        private const val KEYSTORE = "AndroidKeyStore"

        fun create(challenge: Challenge, alias: String): KeystoreAttestation {
            // Prefer StrongBox, then fall back to the TEE. Device-property attestation
            // (brand/model/etc. inside the attestation) isn't supported everywhere.
            val attempts = listOf(true to true, true to false, false to true, false to false)
            var lastError: Exception? = null
            for ((strongBox, deviceProps) in attempts) {
                try {
                    generate(challenge, alias, strongBox, deviceProps)
                    return load(alias)
                } catch (e: StrongBoxUnavailableException) {
                    lastError = e
                } catch (e: ProviderException) {
                    lastError = e
                } catch (e: SecurityException) {
                    lastError = e
                }
            }
            throw IllegalStateException("could not create an attested key", lastError)
        }

        private fun generate(challenge: Challenge, alias: String, strongBox: Boolean, deviceProps: Boolean) {
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge.bytes)
                .setIsStrongBoxBacked(strongBox)
                .apply {
                    if (deviceProps && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                        setDevicePropertiesAttestationIncluded(true)
                    }
                }
                .build()
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE).run {
                initialize(spec)
                generateKeyPair()
            }
        }

        private fun load(alias: String): KeystoreAttestation {
            val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            val key = ks.getKey(alias, null) as PrivateKey
            val chain = ks.getCertificateChain(alias)?.map { it.encoded }
                ?: throw IllegalStateException("keystore returned no attestation chain")
            return KeystoreAttestation(key, chain, securityLevel(key))
        }

        private fun securityLevel(key: PrivateKey): Record.SecurityLevel {
            val info = KeyFactory.getInstance(key.algorithm, KEYSTORE).getKeySpec(key, KeyInfo::class.java)
            return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                when (info.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> Record.SecurityLevel.STRONGBOX
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> Record.SecurityLevel.TEE
                    else -> Record.SecurityLevel.SOFTWARE
                }
            } else {
                @Suppress("DEPRECATION")
                if (info.isInsideSecureHardware) Record.SecurityLevel.TEE else Record.SecurityLevel.SOFTWARE
            }
        }
    }
}
