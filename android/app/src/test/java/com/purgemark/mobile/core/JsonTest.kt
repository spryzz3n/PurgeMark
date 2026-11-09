package com.purgemark.mobile.core

import java.io.File
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class JsonTest {
    @Test
    fun keyOrderFollowsUtf16CodeUnits() {
        // RFC 8785 §3.2.3: U+1F600 (surrogates D83D DE00) sorts before U+FB33.
        val v = Json.parse("""{"\ufb33":1,"\ud83d\ude00":2,"\u20ac":3,"\u00f6":4,"\u0080":5,"1":6,"\r":7}""")
        assertEquals("{\"\\r\":7,\"1\":6,\"\u0080\":5,\"\u00f6\":4,\"\u20ac\":3,\"\ud83d\ude00\":2,\"\ufb33\":1}", v.canonical())
    }

    @Test
    fun escapingMatchesJcs() {
        val s = Json.str("q\"b\\n\n\u0001/\u007f")
        assertEquals("\"q\\\"b\\\\n\\n\\u0001/\u007f\"", s.canonical())
    }

    @Test
    fun whitespaceAndOrderDoNotMatter() {
        assertEquals("""{"a":[true,null,"x"],"b":1}""", Json.parse(""" { "b": 1, "a": [true, null, "x"] } """).canonical())
    }

    @Test
    fun rejectsWhatTheOtherImplementationsReject() {
        assertThrows(JsonParseException::class.java) { Json.parse("1.5") }
        assertThrows(JsonParseException::class.java) { Json.parse("9007199254740992") }
        assertThrows(JsonParseException::class.java) { Json.parse("""{"a":1,"a":2}""") }
        assertThrows(JsonParseException::class.java) { Json.parse("""{"a":1} x""") }
        assertThrows(IllegalArgumentException::class.java) { Json.Num(9_007_199_254_740_992L) }
        assertThrows(IllegalArgumentException::class.java) { Json.str("\ud800").canonical() }
        assertEquals("9007199254740991", Json.parse("9007199254740991").canonical())
    }

    /**
     * A certificate signed by the C++ `pmark` tool (with non-ASCII text in it) must
     * verify here, which only works if Kotlin canonicalizes to the same bytes.
     */
    @Test
    fun verifiesCertificateSignedByTheCppTool() {
        val fixture = File("../../verifier/fixtures/valid-certificate.json")
        assertTrue("fixture not found at ${fixture.absolutePath}", fixture.exists())
        val cert = Json.parse(fixture.readText()) as Json.Obj
        val signer = cert["signer"] as Json.Obj
        val raw = Base64.getDecoder().decode((signer["public_key"] as Json.Str).value)
        val spki = byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00) + raw
        val publicKey = KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(spki))

        val body = Json.Obj(cert.fields - "signature").canonical().toByteArray(Charsets.UTF_8)
        val sig = Base64.getDecoder().decode((cert["signature"] as Json.Str).value)
        val verifier = Signature.getInstance("Ed25519").apply { initVerify(publicKey); update(body) }
        assertTrue("C++ signature must verify over Kotlin's canonical form", verifier.verify(sig))

        // And any change breaks it.
        val tampered = Json.Obj(cert.fields - "signature" + ("result" to Json.str("sanitized!"))).canonical()
        val v2 = Signature.getInstance("Ed25519").apply { initVerify(publicKey); update(tampered.toByteArray()) }
        assertTrue(!v2.verify(sig))
    }
}
