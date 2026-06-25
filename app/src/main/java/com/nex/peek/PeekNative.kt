package com.nex.peek

import com.nex.peek.model.FunctionInfo
import com.nex.peek.model.InstructionInfo
import com.nex.peek.model.SymbolInfo
import com.nex.peek.model.XrefInfo

/**
 * Thin Kotlin wrapper around the peek_native JNI library.
 *
 * All binary-level logic (ELF parsing, disassembly, xref detection,
 * SQLite caching) lives entirely in C++. This object is a typed
 * facade over the raw JNI array protocol.
 */
object PeekNative {

    init {
        System.loadLibrary("peek_native")
    }

    // -----------------------------------------------------------------------
    // Handle lifecycle
    // -----------------------------------------------------------------------

    /** Opens a .so file for analysis (or loads from cache). Returns 0 on failure. */
    fun openBinary(path: String, dbDir: String): Long =
        nativeOpenBinary(path, dbDir)

    /** Releases the native context. Must be called when done. */
    fun closeBinary(handle: Long) {
        if (handle != 0L) nativeCloseBinary(handle)
    }

    /** Returns the last error string from a handle (empty if none). */
    fun getLastError(handle: Long): String =
        if (handle == 0L) "null handle" else nativeGetLastError(handle)

    // -----------------------------------------------------------------------
    // Queries — all delegate to SQLite via C++
    // -----------------------------------------------------------------------

    fun getFunctionList(handle: Long): List<FunctionInfo> {
        if (handle == 0L) return emptyList()
        val longs  = nativeGetFunctionList(handle)   // [id, addr, size, kind, ...]
        val names  = nativeGetFunctionNames(handle)  // [name, ...]
        val count  = longs.size / 4
        return List(count) { i ->
            FunctionInfo(
                id      = longs[i * 4],
                address = longs[i * 4 + 1].toULong(),
                size    = longs[i * 4 + 2].toULong(),
                name    = names.getOrElse(i) { "" },
                kind    = longs[i * 4 + 3].toInt()
            )
        }
    }

    fun getInstructions(
        handle: Long,
        funcId: Long,
        limit: Int  = 200,
        offset: Int = 0
    ): List<InstructionInfo> {
        if (handle == 0L) return emptyList()
        val longs   = nativeGetInstructions(handle, funcId, limit, offset) // [addr, size, ...]
        val strings = nativeGetInstructionStrings(handle, funcId, limit, offset) // [bytes, mnem, ops, ...]
        val count   = longs.size / 2
        return List(count) { i ->
            InstructionInfo(
                address   = longs[i * 2].toULong(),
                size      = longs[i * 2 + 1].toInt(),
                bytesHex  = strings.getOrElse(i * 3)     { "" },
                mnemonic  = strings.getOrElse(i * 3 + 1) { "" },
                operands  = strings.getOrElse(i * 3 + 2) { "" }
            )
        }
    }

    fun getInstructionCount(handle: Long, funcId: Long): Long =
        if (handle == 0L) 0L else nativeGetInstructionCount(handle, funcId)

    fun getXrefs(handle: Long, address: ULong): List<XrefInfo> {
        if (handle == 0L) return emptyList()
        val longs = nativeGetXrefs(handle, address.toLong())      // [from, to, ...]
        val types = nativeGetXrefTypes(handle, address.toLong())   // [type, ...]
        val count = longs.size / 2
        return List(count) { i ->
            XrefInfo(
                fromAddress = longs[i * 2].toULong(),
                toAddress   = longs[i * 2 + 1].toULong(),
                refType     = types.getOrElse(i) { "branch" }
            )
        }
    }

    fun getSymbols(handle: Long): List<SymbolInfo> {
        if (handle == 0L) return emptyList()
        val longs   = nativeGetSymbols(handle)       // [addr, isImport, ...]
        val strings = nativeGetSymbolStrings(handle) // [name, typeStr, ...]
        val count   = longs.size / 2
        return List(count) { i ->
            SymbolInfo(
                address  = longs[i * 2].toULong(),
                name     = strings.getOrElse(i * 2)     { "" },
                typeStr  = strings.getOrElse(i * 2 + 1) { "other" },
                isImport = longs[i * 2 + 1] != 0L
            )
        }
    }

    // -----------------------------------------------------------------------
    // Decompiler
    // -----------------------------------------------------------------------

    /**
     * One-time init: registers the SLEIGH spec directory (assets extracted
     * to filesDir/decompiler_spec). Must be called before decompileFunction.
     * Returns true on success.
     */
    fun initDecompiler(specDir: String): Boolean = nativeInitDecompiler(specDir)

    /**
     * Decompile a single function identified by its DB id.
     * Runs the full Ghidra pipeline on the function's raw bytes and caches
     * the pseudocode in SQLite. Returns empty string on failure.
     */
    fun decompileFunction(handle: Long, funcId: Long): String =
        if (handle == 0L) "" else nativeDecompileFunction(handle, funcId)

    // -----------------------------------------------------------------------
    // Raw JNI declarations
    // -----------------------------------------------------------------------

    @JvmStatic private external fun nativeOpenBinary(path: String, dbDir: String): Long
    @JvmStatic private external fun nativeCloseBinary(handle: Long)
    @JvmStatic private external fun nativeGetLastError(handle: Long): String
    @JvmStatic private external fun nativeInstallCrashHandler(crashFilePath: String)

    /**
     * Installs a native (C/C++ level) signal handler so that a real crash
     * (SIGSEGV/SIGABRT/etc, the kind that kills the process with no Java
     * exception at all) writes a short reason to [crashFilePath] before
     * the process dies. Call once, as early as possible (Application.onCreate).
     */
    @JvmStatic fun installNativeCrashHandler(crashFilePath: String) {
        nativeInstallCrashHandler(crashFilePath)
    }

    @JvmStatic private external fun nativeGetFunctionList(handle: Long): LongArray
    @JvmStatic private external fun nativeGetFunctionNames(handle: Long): Array<String>

    @JvmStatic private external fun nativeGetInstructions(handle: Long, funcId: Long, limit: Int, offset: Int): LongArray
    @JvmStatic private external fun nativeGetInstructionStrings(handle: Long, funcId: Long, limit: Int, offset: Int): Array<String>
    @JvmStatic private external fun nativeGetInstructionCount(handle: Long, funcId: Long): Long

    @JvmStatic private external fun nativeGetXrefs(handle: Long, address: Long): LongArray
    @JvmStatic private external fun nativeGetXrefTypes(handle: Long, address: Long): Array<String>

    @JvmStatic private external fun nativeGetSymbols(handle: Long): LongArray
    @JvmStatic private external fun nativeGetSymbolStrings(handle: Long): Array<String>

    @JvmStatic private external fun nativeInitDecompiler(specDir: String): Boolean
    @JvmStatic private external fun nativeDecompileFunction(handle: Long, funcId: Long): String
}
