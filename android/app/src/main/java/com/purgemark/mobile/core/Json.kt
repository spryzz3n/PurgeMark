package com.purgemark.mobile.core

// Minimal JSON model with an RFC 8785 (JCS) canonical writer, matching
// core/src/canonical_json.cpp and verifier/pm-verify.js: integers only (|n| <= 2^53-1),
// object keys sorted by UTF-16 code units, minimal string escaping.

sealed class Json {
    object Null : Json()
    data class Bool(val value: Boolean) : Json()
    data class Num(val value: Long) : Json() {
        init {
            require(value in -MAX_SAFE..MAX_SAFE) { "integer outside ±2^53" }
        }
    }
    data class Str(val value: String) : Json()
    data class Arr(val items: List<Json>) : Json()
    data class Obj(val fields: Map<String, Json>) : Json() {
        operator fun get(key: String): Json? = fields[key]
    }

    fun canonical(): String = StringBuilder().also { writeCanonical(this, it) }.toString()

    companion object {
        const val MAX_SAFE = 9_007_199_254_740_991L

        fun obj(vararg pairs: Pair<String, Json>) = Obj(linkedMapOf(*pairs))
        fun str(s: String) = Str(s)
        fun num(n: Long) = Num(n)
        fun num(n: Int) = Num(n.toLong())
        fun bool(b: Boolean) = Bool(b)
        fun arr(items: List<Json>) = Arr(items)

        fun parse(text: String): Json = Parser(text).parseDocument()
    }
}

private fun writeCanonical(v: Json, out: StringBuilder) {
    when (v) {
        Json.Null -> out.append("null")
        is Json.Bool -> out.append(if (v.value) "true" else "false")
        is Json.Num -> out.append(v.value)
        is Json.Str -> writeString(v.value, out)
        is Json.Arr -> {
            out.append('[')
            v.items.forEachIndexed { i, item ->
                if (i > 0) out.append(',')
                writeCanonical(item, out)
            }
            out.append(']')
        }
        is Json.Obj -> {
            out.append('{')
            // Kotlin strings are UTF-16, so natural String order is JCS key order.
            v.fields.keys.sorted().forEachIndexed { i, key ->
                if (i > 0) out.append(',')
                writeString(key, out)
                out.append(':')
                writeCanonical(v.fields.getValue(key), out)
            }
            out.append('}')
        }
    }
}

private fun writeString(s: String, out: StringBuilder) {
    // An unpaired surrogate has no UTF-8 encoding; the C++ side rejects it too.
    var k = 0
    while (k < s.length) {
        val c = s[k]
        if (c.isHighSurrogate() && k + 1 < s.length && s[k + 1].isLowSurrogate()) k += 2
        else if (c.isSurrogate()) throw IllegalArgumentException("string contains an unpaired surrogate")
        else k++
    }
    out.append('"')
    for (c in s) {
        when (c) {
            '"' -> out.append("\\\"")
            '\\' -> out.append("\\\\")
            '\b' -> out.append("\\b")
            '\u000C' -> out.append("\\f")
            '\n' -> out.append("\\n")
            '\r' -> out.append("\\r")
            '\t' -> out.append("\\t")
            else -> if (c < ' ') out.append("\\u%04x".format(c.code)) else out.append(c)
        }
    }
    out.append('"')
}

class JsonParseException(message: String) : IllegalArgumentException(message)

private class Parser(private val s: String) {
    private var i = 0

    fun parseDocument(): Json {
        val v = value()
        skipWs()
        if (i != s.length) fail("trailing characters")
        return v
    }

    private fun fail(msg: String): Nothing = throw JsonParseException("$msg at offset $i")

    private fun skipWs() {
        while (i < s.length && s[i] in " \t\r\n") i++
    }

    private fun value(): Json {
        skipWs()
        if (i >= s.length) fail("unexpected end")
        return when (s[i]) {
            '{' -> obj()
            '[' -> arr()
            '"' -> Json.Str(string())
            't' -> literal("true", Json.Bool(true))
            'f' -> literal("false", Json.Bool(false))
            'n' -> literal("null", Json.Null)
            else -> number()
        }
    }

    private fun literal(word: String, v: Json): Json {
        if (!s.startsWith(word, i)) fail("bad literal")
        i += word.length
        return v
    }

    private fun obj(): Json {
        i++ // {
        val fields = linkedMapOf<String, Json>()
        skipWs()
        if (i < s.length && s[i] == '}') {
            i++
            return Json.Obj(fields)
        }
        while (true) {
            skipWs()
            if (i >= s.length || s[i] != '"') fail("expected key")
            val key = string()
            skipWs()
            if (i >= s.length || s[i] != ':') fail("expected ':'")
            i++
            if (fields.put(key, value()) != null) fail("duplicate key \"$key\"")
            skipWs()
            if (i >= s.length) fail("unterminated object")
            when (s[i++]) {
                ',' -> continue
                '}' -> return Json.Obj(fields)
                else -> fail("expected ',' or '}'")
            }
        }
    }

    private fun arr(): Json {
        i++ // [
        val items = mutableListOf<Json>()
        skipWs()
        if (i < s.length && s[i] == ']') {
            i++
            return Json.Arr(items)
        }
        while (true) {
            items.add(value())
            skipWs()
            if (i >= s.length) fail("unterminated array")
            when (s[i++]) {
                ',' -> continue
                ']' -> return Json.Arr(items)
                else -> fail("expected ',' or ']'")
            }
        }
    }

    private fun string(): String {
        i++ // opening quote
        val sb = StringBuilder()
        while (true) {
            if (i >= s.length) fail("unterminated string")
            val c = s[i++]
            when {
                c == '"' -> return sb.toString()
                c == '\\' -> {
                    if (i >= s.length) fail("bad escape")
                    when (val e = s[i++]) {
                        '"', '\\', '/' -> sb.append(e)
                        'b' -> sb.append('\b')
                        'f' -> sb.append('\u000C')
                        'n' -> sb.append('\n')
                        'r' -> sb.append('\r')
                        't' -> sb.append('\t')
                        'u' -> {
                            if (i + 4 > s.length) fail("bad \\u escape")
                            sb.append(s.substring(i, i + 4).toIntOrNull(16)?.toChar() ?: fail("bad \\u escape"))
                            i += 4
                        }
                        else -> fail("bad escape")
                    }
                }
                c < ' ' -> fail("control character in string")
                else -> sb.append(c)
            }
        }
    }

    private fun number(): Json {
        val start = i
        if (i < s.length && s[i] == '-') i++
        while (i < s.length && s[i].isDigit()) i++
        if (i < s.length && s[i] in ".eE") fail("only integers are supported")
        val text = s.substring(start, i)
        val n = text.toLongOrNull() ?: fail("bad number")
        if (n !in -Json.MAX_SAFE..Json.MAX_SAFE) fail("integer outside ±2^53")
        return Json.Num(n)
    }
}
