package com.kyhsgeekcode.filechooser.model

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.InputStream
import java.security.MessageDigest

//class ExpandedFileCache(private val cacheDir: File) {
suspend fun getExpandedFile(cacheDir: File, sourceFile: File): File {
    val title = withContext(Dispatchers.IO) {
        buildExpandedFileCacheKey(sourceFile)
    }
    return File(cacheDir, title)
}

internal fun buildExpandedFileCacheKey(sourceFile: File): String {
    sourceFile.inputStream().buffered().use { input ->
        return buildExpandedFileCacheKey(input)
    }
}

internal fun buildExpandedFileCacheKey(inputStream: InputStream): String {
    val digest = MessageDigest.getInstance("SHA-256")
    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
    while (true) {
        val read = inputStream.read(buffer)
        if (read < 0) {
            break
        }
        if (read > 0) {
            digest.update(buffer, 0, read)
        }
    }
    return digest.digest().joinToString("") { byte -> "%02x".format(byte) }
}
//} 
