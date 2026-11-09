package com.purgemark.mobile.core

import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RecordTest {
    // A stand-in for the Android Keystore key: same algorithm, software key.
    private class FakeKey : Record.AttestedKey {
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        override val securityLevel = Record.SecurityLevel.TEE
        override val chainDer = listOf(byteArrayOf(1, 2, 3), byteArrayOf(4, 5))
        override fun sign(message: ByteArray): ByteArray =
            Signature.getInstance("SHA256withECDSA").run { initSign(pair.private); update(message); sign() }
    }

    private val device = Record.Device("Google", "google", "Pixel 9", "tokay", "tokay", 36, "16", "2026-10-05", "google/tokay/...")
    private val posture = Posture(Posture.Encryption.FILE_BASED, true, true, false)

    @Test
    fun challengeQrRoundTrip() {
        val bytes = ByteArray(Challenge.SIZE) { it.toByte() }
        val c = Challenge.fromQr(Challenge.qrPayload(bytes))
        assertNotNull(c)
        assertArrayEquals(bytes, c!!.bytes)
        assertEquals(Challenge.Source.STATION, c.source)
        assertNotNull(Challenge.fromQr("  " + Challenge.qrPayload(bytes) + "\n"))
    }

    @Test
    fun challengeRejectsAnythingElse() {
        assertNull(Challenge.fromQr("https://example.com"))
        assertNull(Challenge.fromQr(Challenge.PREFIX + "short"))
        assertNull(Challenge.fromQr(Challenge.PREFIX + "!!!not-base64!!!"))
        assertNull(Challenge.fromQr(Challenge.qrPayload(ByteArray(16))))
        assertEquals(Challenge.Source.SELF, Challenge.selfGenerated().source)
    }

    @Test
    fun recordIsSignedOverItsCanonicalForm() {
        val key = FakeKey()
        val challenge = Challenge.fromQr(Challenge.qrPayload(ByteArray(32) { 7 }))!!
        val record = Record.build(challenge, device, posture, "2026-10-30T12:00:00Z", key, recordId = "r-1")

        assertEquals(Record.SCHEMA, (record["schema"] as Json.Str).value)
        assertEquals(challenge.encoded, ((record["challenge"] as Json.Obj)["value"] as Json.Str).value)
        assertEquals("factory-reset-crypto-erase", (record["intended_method"] as Json.Str).value)
        assertEquals(2, (((record["key"] as Json.Obj)["attestation_chain"]) as Json.Arr).items.size)

        val sig = Base64.getDecoder().decode((record["signature"] as Json.Str).value)
        val ok = Signature.getInstance("SHA256withECDSA").run {
            initVerify(key.pair.public)
            update(Record.signedBytes(record))
            verify(sig)
        }
        assertTrue(ok)

        // Survives a print/parse round trip (what the station does), and tampering breaks it.
        val reparsed = Json.parse(record.canonical()) as Json.Obj
        assertArrayEquals(Record.signedBytes(record), Record.signedBytes(reparsed))
        val tampered = Json.Obj(reparsed.fields + ("created_at" to Json.str("2020-01-01T00:00:00Z")))
        val bad = Signature.getInstance("SHA256withECDSA").run {
            initVerify(key.pair.public); update(Record.signedBytes(tampered)); verify(sig)
        }
        assertFalse(bad)
    }

    @Test
    fun unencryptedPhoneIsBlocked() {
        val p = posture.copy(encryption = Posture.Encryption.NONE)
        assertFalse(p.resetIsCryptoErase)
        assertTrue(p.findings().any { it.severity == Posture.Severity.BLOCKER })
        assertTrue(posture.findings().none { it.severity == Posture.Severity.BLOCKER })
        assertEquals("factory-reset", (Record.build(
            Challenge.selfGenerated(), device, p, "2026-10-30T12:00:00Z", FakeKey(),
        )["intended_method"] as Json.Str).value)
    }
}
