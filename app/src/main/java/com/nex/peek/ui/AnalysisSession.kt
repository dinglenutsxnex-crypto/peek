package com.nex.peek.ui

/**
 * Simple process-scoped holder for the current analysis handle.
 * The handle is an opaque pointer (jlong) to a native AnalysisContext.
 * It must be closed via PeekNative.closeBinary() when no longer needed.
 */
object AnalysisSession {
    @Volatile private var handle: Long = 0L

    fun set(h: Long) { handle = h }
    fun get(): Long  = handle
    fun clear()      = set(0L)
    fun isValid()    = handle != 0L
}
