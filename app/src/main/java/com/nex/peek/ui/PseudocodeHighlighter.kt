package com.nex.peek.ui

import android.graphics.Typeface
import android.text.Spannable
import android.text.SpannableStringBuilder
import android.text.SpannableString
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan

internal object PseudocodeHighlighter {

    // Atom One Dark token palette
    private const val COLOR_COMMENT  = 0xFF5C6370.toInt()  // grey
    private const val COLOR_STRING   = 0xFF98C379.toInt()  // green
    private const val COLOR_NUMBER   = 0xFFD19A66.toInt()  // orange
    private const val COLOR_KEYWORD  = 0xFFC678DD.toInt()  // purple
    private const val COLOR_TYPE     = 0xFFE5C07B.toInt()  // yellow
    private const val COLOR_FUNCTION = 0xFF61AFEF.toInt()  // blue

    private data class Rule(val regex: Regex, val color: Int, val italic: Boolean = false)

    private val RULES: List<Rule> = listOf(

        // ── Comments (highest priority — suppress all inner tokens) ──────────
        Rule(
            Regex("""/\*.*?\*/""", setOf(RegexOption.DOT_MATCHES_ALL)),
            COLOR_COMMENT, italic = true
        ),
        Rule(Regex("""//[^\n]*"""), COLOR_COMMENT, italic = true),

        // ── String literals ──────────────────────────────────────────────────
        Rule(Regex(""""[^"\\]*(?:\\.[^"\\]*)*""""), COLOR_STRING),

        // ── Numeric literals (hex before decimal) ────────────────────────────
        Rule(Regex("""0[xX][0-9A-Fa-f]+[uUlL]*"""), COLOR_NUMBER),
        Rule(Regex("""\b[0-9]+[uUlL]*\b"""),         COLOR_NUMBER),

        // ── Control-flow keywords ────────────────────────────────────────────
        Rule(
            Regex("""\b(?:if|else|while|for|do|return|break|continue|switch|case|default|goto)\b"""),
            COLOR_KEYWORD
        ),

        // ── Storage / qualifier keywords ─────────────────────────────────────
        Rule(
            Regex("""\b(?:const|static|extern|volatile|inline|register|typedef|struct|union|enum|auto|signed|unsigned)\b"""),
            COLOR_KEYWORD
        ),

        // ── Primitive C types ────────────────────────────────────────────────
        Rule(
            Regex("""\b(?:void|bool|char|short|int|long|float|double|size_t|ssize_t|ptrdiff_t|uintptr_t|intptr_t|int8_t|int16_t|int32_t|int64_t|uint8_t|uint16_t|uint32_t|uint64_t)\b"""),
            COLOR_TYPE
        ),

        // ── Ghidra pseudo-types ───────────────────────────────────────────────
        // Matches: int8/int4/int2/int1, uint8…, undefined8/4/2/1/undefined,
        //          xunknown8/4/2/1, code
        Rule(
            Regex("""\b(?:u?int(?:8|4|2|1)|undefined(?:8|4|2|1)?|xunknown(?:8|4|2|1)|code)\b"""),
            COLOR_TYPE
        ),

        // ── JNI types ────────────────────────────────────────────────────────
        Rule(
            Regex("""\b(?:JavaVM|JNIEnv|jobject|jclass|jint|jlong|jshort|jbyte|jchar|jboolean|jfloat|jdouble|jstring|jthrowable|jweak|jarray|jobjectArray|jbyteArray|jcharArray|jshortArray|jintArray|jlongArray|jfloatArray|jdoubleArray|jbooleanArray)\b"""),
            COLOR_TYPE
        ),

        // ── Function / call targets — identifier immediately before '(' ───────
        Rule(
            Regex("""\b[A-Za-z_][A-Za-z0-9_]*(?=\s*\()"""),
            COLOR_FUNCTION
        ),
    )

    /**
     * Returns a [SpannableString] with Atom One Dark syntax colours applied.
     * Rules are evaluated left-to-right in priority order; once a character is
     * claimed by a higher-priority rule it is never re-coloured.
     *
     * Falls back to plain [SpannableString] if any exception occurs so the
     * fragment always has something to display.
     */
    fun highlight(code: String): SpannableString {
        return try {
            applyRules(code)
        } catch (_: Exception) {
            SpannableString(code)
        }
    }

    private fun applyRules(code: String): SpannableString {
        val sb       = SpannableStringBuilder(code)
        val consumed = BooleanArray(code.length)

        for (rule in RULES) {
            for (match in rule.regex.findAll(code)) {
                val start = match.range.first
                val end   = match.range.last + 1
                // Skip if any character was already claimed by a higher rule.
                if ((start until end).any { consumed[it] }) continue
                sb.setSpan(
                    ForegroundColorSpan(rule.color),
                    start, end,
                    Spannable.SPAN_INCLUSIVE_EXCLUSIVE
                )
                if (rule.italic) {
                    sb.setSpan(
                        StyleSpan(Typeface.ITALIC),
                        start, end,
                        Spannable.SPAN_INCLUSIVE_EXCLUSIVE
                    )
                }
                for (i in start until end) consumed[i] = true
            }
        }

        return SpannableString.valueOf(sb)
    }
}
