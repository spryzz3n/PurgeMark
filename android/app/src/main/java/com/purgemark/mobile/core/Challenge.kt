package com.purgemark.mobile.core

import java.security.SecureRandom
import java.util.Base64

/**
 * The one-time value baked into the key attestation, so a record can't be
 * prepared in advance or replayed. A station (`pmark android begin`) shows it as a
 * QR code; without a station the phone makes its own, which the record says.
 */
class Challenge private constructor(val bytes: ByteArray, val source: Source) {
    enum class Source(val wire: String) { STATION("station"), SELF("self") }

    val encoded: String get() = B64URL.encodeToString(bytes)

    companion object {
        const val PREFIX = "purgemark-challenge:v1:"
        const val SIZE = 32
        private val B64URL = Base64.getUrlEncoder().withoutPadding()

        /** Parses a station QR payload; null if it isn't one. */
        fun fromQr(text: String): Challenge? {
            val t = text.trim()
            if (!t.startsWith(PREFIX)) return null
            val bytes = try {
                Base64.getUrlDecoder().decode(t.removePrefix(PREFIX))
            } catch (e: IllegalArgumentException) {
                return null
            }
            return if (bytes.size == SIZE) Challenge(bytes, Source.STATION) else null
        }

        fun selfGenerated(random: SecureRandom = SecureRandom()): Challenge =
            Challenge(ByteArray(SIZE).also(random::nextBytes), Source.SELF)

        fun qrPayload(bytes: ByteArray): String = PREFIX + B64URL.encodeToString(bytes)
    }
}
