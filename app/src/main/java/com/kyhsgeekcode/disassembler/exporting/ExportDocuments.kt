package com.kyhsgeekcode.disassembler.exporting

import android.content.ContentResolver
import android.net.Uri
import com.kyhsgeekcode.toValidFileName
import java.io.File
import java.io.IOException

fun buildProjectExportFileName(projectName: String): String {
    return "DisassemblerProject_${projectName.toValidFileName()}.zip"
}

fun buildBinaryDetailsExportFileName(sourcePath: String): String {
    val sourceName = File(sourcePath).name.toValidFileName()
    if (sourceName.isBlank()) {
        return "details.txt"
    }
    return "${sourceName}_details.txt"
}

@Throws(IOException::class)
fun writeTextDocument(contentResolver: ContentResolver, destinationUri: Uri, text: String) {
    contentResolver.openOutputStream(destinationUri)?.bufferedWriter().use { writer ->
        requireNotNull(writer) { "Failed to open destination URI: $destinationUri" }
        writer.write(text)
    }
}

@Throws(IOException::class)
fun copyFileToDocument(contentResolver: ContentResolver, sourceFile: File, destinationUri: Uri) {
    contentResolver.openOutputStream(destinationUri)?.use { outputStream ->
        requireNotNull(outputStream) { "Failed to open destination URI: $destinationUri" }
        sourceFile.inputStream().use { inputStream ->
            inputStream.copyTo(outputStream)
        }
    }
}
