package com.nex.peek.ui

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.util.AttributeSet
import android.view.View

/**
 * Draws a 45° diagonal scanline pattern edge-to-edge.
 * Very low opacity — purely a texture hint behind all UI.
 */
class ScanlineView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyle: Int = 0
) : View(context, attrs, defStyle) {

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        // Slightly lighter than bg_surface (#222228) — barely visible
        color = 0x08FFFFFF.toInt()   // ~3% white
        strokeWidth = 1f
        style = Paint.Style.STROKE
    }

    // Gap between parallel diagonal lines in dp, converted to px
    private val spacingPx = (8 * context.resources.displayMetrics.density)

    override fun onDraw(canvas: Canvas) {
        val w = width.toFloat()
        val h = height.toFloat()
        if (w == 0f || h == 0f) return

        // Draw lines at 45°: each line goes from (x, 0) to (0, x) or
        // from (w, y) to (y, h) — covering all diagonals across the rect.
        // We iterate over the diagonal offset covering the full diagonal range.
        val diag = w + h
        var offset = 0f
        while (offset < diag) {
            // Start point: on the top edge if offset < w, else on the left edge
            val startX: Float
            val startY: Float
            if (offset <= w) {
                startX = offset
                startY = 0f
            } else {
                startX = 0f
                startY = offset - w
            }
            // End point: on the left edge if offset < h, else on the bottom edge
            val endX: Float
            val endY: Float
            if (offset <= h) {
                endX = 0f
                endY = offset
            } else {
                endX = offset - h
                endY = h
            }
            canvas.drawLine(startX, startY, endX, endY, paint)
            offset += spacingPx
        }
    }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        super.onMeasure(widthMeasureSpec, heightMeasureSpec)
    }
}
