package com.nex.peek.ui

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Typeface
import android.text.Layout
import android.text.Spannable
import android.text.SpannableString
import android.text.SpannableStringBuilder
import android.text.StaticLayout
import android.text.TextPaint
import android.util.AttributeSet
import android.view.View

/**
 * IDA-style pseudocode renderer: line numbers | separator | highlighted code.
 * Draws indent-guide lines at each indentation level (à la VS Code / IDA Pro).
 */
class PseudocodeView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyle: Int = 0
) : View(context, attrs, defStyle) {

    private val density = context.resources.displayMetrics.density
    private fun dp(v: Float) = v * density

    private val lineNumColor    = 0xFF4A5568.toInt()
    private val separatorColor  = 0xFF2D3748.toInt()
    // Indent guide lines — same dim colour, very subtle
    private val indentGuideColor = 0xFF2A3444.toInt()

    private val gutterPadL      = dp(8f)
    private val gutterPadR      = dp(8f)
    private val codePadL        = dp(10f)
    private val topPad          = dp(12f)
    private val bottomPad       = dp(56f)
    private val textSizePx      = dp(12f)
    private val lineSpacingMult = 1.25f

    private val numPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        typeface  = Typeface.MONOSPACE
        textSize  = textSizePx
        color     = lineNumColor
        textAlign = Paint.Align.RIGHT
    }

    private val sepPaint = Paint().apply {
        color       = separatorColor
        strokeWidth = dp(1f)
        style       = Paint.Style.STROKE
    }

    private val indentGuidePaint = Paint().apply {
        color       = indentGuideColor
        strokeWidth = dp(1f)
        style       = Paint.Style.STROKE
    }

    private val codePaint = TextPaint(Paint.ANTI_ALIAS_FLAG).apply {
        typeface = Typeface.MONOSPACE
        textSize = textSizePx
        color    = 0xFFE8E8F0.toInt()
    }

    // Per-line spannables and their pre-built layouts
    private var lineSpans: List<SpannableString> = emptyList()
    private var lineLayouts: List<StaticLayout>  = emptyList()

    // Indent levels per line (number of leading spaces / indentUnitSpaces)
    private var lineIndents: List<Int> = emptyList()

    private var numRightX    = 0f
    private var separatorX  = 0f
    private var codeStartX  = 0f
    private var charWidth    = 0f   // width of one monospace character
    private var totalHeight  = 0

    // How many spaces == one indent level. Auto-detected from code.
    private var indentUnitSpaces = 4

    // ── Public API ────────────────────────────────────────────────────────────

    fun setCode(full: SpannableString) {
        indentUnitSpaces = detectIndentUnit(full.toString())
        lineSpans   = splitByLine(full)
        lineIndents = lineSpans.map { countIndentLevel(it.toString()) }
        requestLayout()
        invalidate()
    }

    // ── Indent detection ──────────────────────────────────────────────────────

    /** Detect the smallest non-zero leading-space count as the indent unit. */
    private fun detectIndentUnit(code: String): Int {
        val counts = code.lines()
            .map { line -> line.length - line.trimStart().length }
            .filter { it > 0 }
            .toSortedSet()
        // Find the GCD of all indent sizes → that's the unit
        return if (counts.isEmpty()) 4
        else counts.reduce { a, b -> gcd(a, b) }.coerceAtLeast(1)
    }

    private fun gcd(a: Int, b: Int): Int = if (b == 0) a else gcd(b, a % b)

    private fun countIndentLevel(line: String): Int {
        val spaces = line.length - line.trimStart().length
        return spaces / indentUnitSpaces
    }

    // ── Span splitting ────────────────────────────────────────────────────────

    private fun splitByLine(full: SpannableString): List<SpannableString> {
        val text   = full.toString()
        val result = mutableListOf<SpannableString>()
        var lineStart = 0

        while (lineStart <= text.length) {
            val lineEnd = text.indexOf('\n', lineStart).let { if (it < 0) text.length else it }
            val sub     = SpannableStringBuilder(text.substring(lineStart, lineEnd))

            full.getSpans(lineStart, lineEnd, Any::class.java).forEach { span ->
                val ss = (full.getSpanStart(span) - lineStart).coerceAtLeast(0)
                val se = (full.getSpanEnd(span)   - lineStart).coerceAtMost(lineEnd - lineStart)
                if (ss < se) {
                    try { sub.setSpan(span, ss, se, Spannable.SPAN_INCLUSIVE_EXCLUSIVE) } catch (_: Exception) {}
                }
            }

            result.add(SpannableString.valueOf(sub))
            if (lineEnd >= text.length) break
            lineStart = lineEnd + 1
        }
        return result
    }

    // ── Layout ────────────────────────────────────────────────────────────────

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val w = MeasureSpec.getSize(widthMeasureSpec).takeIf { it > 0 }
            ?: context.resources.displayMetrics.widthPixels

        val numDigits = lineSpans.size.toString().length.coerceAtLeast(3)
        val sampleNum = "8".repeat(numDigits)
        numRightX  = gutterPadL + numPaint.measureText(sampleNum)
        separatorX = numRightX + gutterPadR
        codeStartX = separatorX + dp(1f) + codePadL

        // Measure a single character for indent-guide x positions
        charWidth = codePaint.measureText("X")

        val codeWidth = (w - codeStartX).toInt().coerceAtLeast(1)

        lineLayouts = lineSpans.map { span ->
            StaticLayout.Builder
                .obtain(span, 0, span.length, codePaint, codeWidth)
                .setLineSpacing(0f, lineSpacingMult)
                .setAlignment(Layout.Alignment.ALIGN_NORMAL)
                .setIncludePad(false)
                .build()
        }

        totalHeight = (topPad + lineLayouts.sumOf { it.height } + bottomPad).toInt()
        setMeasuredDimension(w, totalHeight)
    }

    // ── Draw ──────────────────────────────────────────────────────────────────

    override fun onDraw(canvas: Canvas) {
        if (lineSpans.isEmpty()) return

        // Gutter separator — full height
        canvas.drawLine(separatorX, 0f, separatorX, totalHeight.toFloat(), sepPaint)

        // ── Compute indent guide segments ─────────────────────────────────────
        // For each indent level that appears, draw a vertical line spanning
        // consecutive lines that are at or deeper than that level.
        //
        // Strategy: accumulate per-guide (level → startY) and close them when
        // a line shallower than the level is encountered.
        //
        // We need to know each line's Y first, so collect them.
        val lineTopY = FloatArray(lineSpans.size)
        val lineH    = IntArray(lineSpans.size)
        var y = topPad
        for (i in lineLayouts.indices) {
            lineTopY[i] = y
            lineH[i]    = lineLayouts[i].height
            y += lineH[i]
        }
        val totalCodeHeight = y

        // Max indent level present
        val maxLevel = (lineIndents.maxOrNull() ?: 0)

        // For each indent level, find runs of lines that have depth >= level
        // and draw a guide at that column.
        for (level in 1..maxLevel) {
            val guideX = codeStartX + level * indentUnitSpaces * charWidth

            var runStart = -1
            for (i in lineSpans.indices) {
                val depth = lineIndents[i]
                val lineText = lineSpans[i].toString().trim()
                // A blank line continues a run but doesn't start one
                val isBlank = lineText.isEmpty()

                if (depth >= level || (isBlank && runStart >= 0)) {
                    if (runStart < 0) runStart = i
                } else {
                    if (runStart >= 0) {
                        // Close run — draw from top of runStart to bottom of i-1
                        val segTop = lineTopY[runStart]
                        val segBot = lineTopY[i - 1] + lineH[i - 1]
                        canvas.drawLine(guideX, segTop, guideX, segBot, indentGuidePaint)
                        runStart = -1
                    }
                }
            }
            // Close any open run at end of file
            if (runStart >= 0) {
                val segTop = lineTopY[runStart]
                val segBot = totalCodeHeight
                canvas.drawLine(guideX, segTop, guideX, segBot, indentGuidePaint)
            }
        }

        // ── Draw line numbers and code ────────────────────────────────────────
        for (i in lineSpans.indices) {
            val layout   = lineLayouts.getOrNull(i) ?: continue
            val baseline = lineTopY[i] + layout.getLineBaseline(0)

            canvas.drawText((i + 1).toString(), numRightX, baseline, numPaint)

            canvas.save()
            canvas.translate(codeStartX, lineTopY[i])
            layout.draw(canvas)
            canvas.restore()
        }
    }
}
