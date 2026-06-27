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
 * IDA-style pseudocode renderer: line numbers | subtle vertical line | highlighted code.
 * No box, no background — pure canvas drawing.
 */
class PseudocodeView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyle: Int = 0
) : View(context, attrs, defStyle) {

    private val density = context.resources.displayMetrics.density
    private fun dp(v: Float) = v * density

    private val lineNumColor   = 0xFF4A5568.toInt()
    private val separatorColor = 0xFF2D3748.toInt()

    private val gutterPadL = dp(8f)
    private val gutterPadR = dp(8f)
    private val codePadL   = dp(10f)
    private val topPad     = dp(12f)
    private val bottomPad  = dp(56f)
    private val textSizePx = dp(12f)
    private val lineSpacingMult = 1.25f

    private val numPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        typeface = Typeface.MONOSPACE
        textSize = textSizePx
        color = lineNumColor
        textAlign = Paint.Align.RIGHT
    }

    private val sepPaint = Paint().apply {
        color = separatorColor
        strokeWidth = dp(1f)
        style = Paint.Style.STROKE
    }

    private val codePaint = TextPaint(Paint.ANTI_ALIAS_FLAG).apply {
        typeface = Typeface.MONOSPACE
        textSize = textSizePx
        color = 0xFFE8E8F0.toInt()
    }

    // Per-line spannables and their pre-built layouts
    private var lineSpans: List<SpannableString> = emptyList()
    private var lineLayouts: List<StaticLayout> = emptyList()

    private var numRightX  = 0f   // x where line number right-edge aligns
    private var separatorX = 0f
    private var codeStartX = 0f
    private var totalHeight = 0

    // ── Public API ────────────────────────────────────────────────────────────

    fun setCode(full: SpannableString) {
        lineSpans = splitByLine(full)
        requestLayout()
        invalidate()
    }

    // ── Span splitting ────────────────────────────────────────────────────────

    private fun splitByLine(full: SpannableString): List<SpannableString> {
        val text = full.toString()
        val result = mutableListOf<SpannableString>()
        var lineStart = 0

        while (lineStart <= text.length) {
            val lineEnd = text.indexOf('\n', lineStart).let { if (it < 0) text.length else it }
            val sub = SpannableStringBuilder(text.substring(lineStart, lineEnd))

            // Copy every span that overlaps this line
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

        // Separator — full height
        canvas.drawLine(separatorX, 0f, separatorX, totalHeight.toFloat(), sepPaint)

        var y = topPad
        lineSpans.forEachIndexed { i, _ ->
            val layout = lineLayouts.getOrNull(i) ?: return@forEachIndexed

            // Baseline of first line in layout for number alignment
            val baseline = y + layout.getLineBaseline(0)
            canvas.drawText((i + 1).toString(), numRightX, baseline, numPaint)

            canvas.save()
            canvas.translate(codeStartX, y)
            layout.draw(canvas)
            canvas.restore()

            y += layout.height
        }
    }
}
