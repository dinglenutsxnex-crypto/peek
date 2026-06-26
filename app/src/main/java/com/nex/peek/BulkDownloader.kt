package com.nex.peek

import android.content.ContentValues
import android.content.Context
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import com.nex.peek.model.FunctionInfo
import java.io.ByteArrayOutputStream
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

object BulkDownloader {

    enum class DownloadType(val label: String, val ext: String) {
        HEX("hex", "hex"),
        ASM("asm", "asm"),
        PSEUDOCODE("pseudocode", "c")
    }

    data class Progress(val done: Int, val total: Int)

    /**
     * Fetches all function data for the given type, builds a zip with one file
     * per function, saves it to the public Downloads folder, and returns the
     * filename (not the full path).
     *
     * Must be called from a background thread / IO dispatcher.
     */
    fun downloadAll(
        context: Context,
        handle: Long,
        functions: List<FunctionInfo>,
        type: DownloadType,
        binaryName: String,
        onProgress: (Progress) -> Unit
    ): String {
        val timestamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
        val zipName = "${sanitize(binaryName)}_${type.label}_$timestamp.zip"

        val zipBytes = buildZip(handle, functions, type, onProgress)
        saveToDownloads(context, zipBytes, zipName)
        return zipName
    }

    // ── Zip construction ──────────────────────────────────────────────────────

    private fun buildZip(
        handle: Long,
        functions: List<FunctionInfo>,
        type: DownloadType,
        onProgress: (Progress) -> Unit
    ): ByteArray {
        val bos = ByteArrayOutputStream()
        ZipOutputStream(bos).use { zos ->
            functions.forEachIndexed { index, fn ->
                val content = generateContent(handle, fn, type)
                val entryName =
                    "${sanitize(fn.displayName)}_${fn.address.toString(16).uppercase()}.${type.ext}"
                zos.putNextEntry(ZipEntry(entryName))
                zos.write(content.toByteArray(Charsets.UTF_8))
                zos.closeEntry()
                onProgress(Progress(index + 1, functions.size))
            }
        }
        return bos.toByteArray()
    }

    // ── Per-type content generators ───────────────────────────────────────────

    private fun generateContent(handle: Long, fn: FunctionInfo, type: DownloadType): String =
        when (type) {
            DownloadType.HEX        -> generateHex(handle, fn)
            DownloadType.ASM        -> generateAsm(handle, fn)
            DownloadType.PSEUDOCODE -> generatePseudocode(handle, fn)
        }

    private fun generateHex(handle: Long, fn: FunctionInfo): String {
        val insns = PeekNative.getInstructions(handle, fn.id, limit = 100_000, offset = 0)
        if (insns.isEmpty()) return "; No data for ${fn.displayName}\n"

        val allBytes = mutableListOf<Byte>()
        val baseAddr = insns.first().address
        for (insn in insns) {
            val hex = insn.bytesHex
            var i = 0
            while (i + 1 < hex.length) {
                allBytes.add(hex.substring(i, i + 2).toInt(16).toByte())
                i += 2
            }
        }

        val sb = StringBuilder()
        sb.append("; ${fn.displayName} @ 0x${fn.address.toString(16).uppercase()}\n\n")
        val bytes = allBytes.toByteArray()
        val rowSize = 16
        var offset = 0
        while (offset < bytes.size) {
            val end = minOf(offset + rowSize, bytes.size)
            val chunk = bytes.copyOfRange(offset, end)
            sb.append(
                (baseAddr + offset.toULong()).toString(16).uppercase().padStart(16, '0')
            )
            sb.append("  ")
            sb.append(chunk.joinToString(" ") { "%02X".format(it) })
            sb.append('\n')
            offset += rowSize
        }
        return sb.toString()
    }

    private fun generateAsm(handle: Long, fn: FunctionInfo): String {
        val count = PeekNative.getInstructionCount(handle, fn.id)
        if (count == 0L) return "; No instructions for ${fn.displayName}\n"

        val sb = StringBuilder()
        sb.append("; ${fn.displayName} @ 0x${fn.address.toString(16).uppercase()}\n\n")

        var offset = 0
        val pageSize = 1_000
        while (offset < count) {
            val insns = PeekNative.getInstructions(handle, fn.id, limit = pageSize, offset = offset)
            if (insns.isEmpty()) break
            for (insn in insns) {
                sb.append(insn.address.toString(16).uppercase().padStart(16, '0'))
                sb.append("  ")
                val separated = buildString {
                    var i = 0
                    val hex = insn.bytesHex
                    while (i + 1 < hex.length) { append(hex.substring(i, i + 2)); append(' '); i += 2 }
                }.trim()
                sb.append(separated.padEnd(12))
                sb.append("  ")
                sb.append(insn.mnemonic)
                if (insn.operands.isNotEmpty()) {
                    sb.append("  ")
                    sb.append(insn.operands)
                }
                sb.append('\n')
            }
            offset += insns.size
        }
        return sb.toString()
    }

    private fun generatePseudocode(handle: Long, fn: FunctionInfo): String {
        val code = PeekNative.decompileFunction(handle, fn.id)
        if (code.isNotEmpty()) return code
        val err = PeekNative.getLastError(handle)
        val reason = if (err.isNotEmpty()) ": $err" else ""
        return "// ${fn.displayName} @ 0x${fn.address.toString(16).uppercase()}\n// Decompilation failed$reason\n"
    }

    // ── Save to public Downloads ──────────────────────────────────────────────

    private fun saveToDownloads(context: Context, data: ByteArray, filename: String) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val values = ContentValues().apply {
                put(MediaStore.Downloads.DISPLAY_NAME, filename)
                put(MediaStore.Downloads.MIME_TYPE, "application/zip")
                put(MediaStore.Downloads.IS_PENDING, 1)
            }
            val uri = context.contentResolver.insert(
                MediaStore.Downloads.EXTERNAL_CONTENT_URI, values
            ) ?: throw IllegalStateException("MediaStore insert failed for Downloads")
            context.contentResolver.openOutputStream(uri)?.use { it.write(data) }
                ?: throw IllegalStateException("Cannot open output stream for $uri")
            values.clear()
            values.put(MediaStore.Downloads.IS_PENDING, 0)
            context.contentResolver.update(uri, values, null, null)
        } else {
            @Suppress("DEPRECATION")
            val dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            dir.mkdirs()
            File(dir, filename).writeBytes(data)
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private fun sanitize(name: String): String =
        name.replace(Regex("[^A-Za-z0-9._\\-]"), "_").take(80)
}
