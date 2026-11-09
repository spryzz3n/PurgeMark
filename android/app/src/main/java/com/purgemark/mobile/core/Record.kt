package com.purgemark.mobile.core

import java.util.Base64
import java.util.UUID

/**
 * The pre-wipe record a station turns into a PurgeMark certificate.
 *
 * It is signed with an ECDSA P-256 key generated inside the phone's secure
 * hardware, and carries that key's attestation chain. The chain proves (to
 * anyone holding Google's attestation roots) that the key lives in genuine
 * secure hardware, the boot state, and that the station's challenge was used,
 * so the record can't be forged on a PC or prepared ahead of time.
 */
object Record {
    const val SCHEMA = "purgemark.android-record/v1"
    const val SIGNATURE_ALGORITHM = "ECDSA-P256-SHA256"

    data class Device(
        val manufacturer: String,
        val brand: String,
        val model: String,
        val device: String,
        val product: String,
        val sdkInt: Int,
        val release: String,
        val securityPatch: String,
        val fingerprint: String,
    ) {
        fun toJson(): Json = Json.obj(
            "manufacturer" to Json.str(manufacturer),
            "brand" to Json.str(brand),
            "model" to Json.str(model),
            "device" to Json.str(device),
            "product" to Json.str(product),
            "sdk_int" to Json.num(sdkInt),
            "release" to Json.str(release),
            "security_patch" to Json.str(securityPatch),
            "fingerprint" to Json.str(fingerprint),
        )
    }

    enum class SecurityLevel(val wire: String) { STRONGBOX("strongbox"), TEE("tee"), SOFTWARE("software") }

    /** The attested key: where it lives, its certificate chain (leaf first), and a way to sign with it. */
    interface AttestedKey {
        val securityLevel: SecurityLevel
        val chainDer: List<ByteArray>
        fun sign(message: ByteArray): ByteArray
    }

    fun build(
        challenge: Challenge,
        device: Device,
        posture: Posture,
        createdAt: String,
        key: AttestedKey,
        recordId: String = UUID.randomUUID().toString(),
    ): Json.Obj {
        val b64 = Base64.getEncoder()
        val body = Json.obj(
            "schema" to Json.str(SCHEMA),
            "record_id" to Json.str(recordId),
            "created_at" to Json.str(createdAt),
            "challenge" to Json.obj(
                "value" to Json.str(challenge.encoded),
                "source" to Json.str(challenge.source.wire),
            ),
            "device" to device.toJson(),
            "posture" to posture.toJson(),
            "intended_method" to Json.str(if (posture.resetIsCryptoErase) "factory-reset-crypto-erase" else "factory-reset"),
            "key" to Json.obj(
                "algorithm" to Json.str(SIGNATURE_ALGORITHM),
                "security_level" to Json.str(key.securityLevel.wire),
                "attestation_chain" to Json.arr(key.chainDer.map { Json.str(b64.encodeToString(it)) }),
            ),
        )
        val signature = key.sign(body.canonical().toByteArray(Charsets.UTF_8))
        return Json.Obj(body.fields + ("signature" to Json.str(b64.encodeToString(signature))))
    }

    /** The exact bytes the signature covers: canonical JSON of everything except "signature". */
    fun signedBytes(record: Json.Obj): ByteArray =
        Json.Obj(record.fields - "signature").canonical().toByteArray(Charsets.UTF_8)
}
