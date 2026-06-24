package com.kyhsgeekcode.disassembler

import com.kyhsgeekcode.extractSupportedArchive
import org.apache.commons.compress.archivers.ar.ArArchiveEntry
import org.apache.commons.compress.archivers.ar.ArArchiveOutputStream
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.FileOutputStream
import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class ArchiveExtractionTest {
    @TempDir
    lateinit var tempDir: Path

    @Test
    fun `extractSupportedArchive extracts zip archives`() {
        val archive = tempDir.resolve("sample.zip")
        ZipOutputStream(FileOutputStream(archive.toFile())).use { zip ->
            zip.putNextEntry(ZipEntry("nested/readme.txt"))
            zip.write("hello zip".encodeToByteArray())
            zip.closeEntry()
        }
        val outputDir = tempDir.resolve("zip-out").toFile()

        extractSupportedArchive(archive.toFile(), outputDir)

        assertEquals(
            "hello zip",
            outputDir.resolve("nested/readme.txt").readText()
        )
    }

    @Test
    fun `extractSupportedArchive extracts ar archives`() {
        val archive = tempDir.resolve("sample.ar")
        ArArchiveOutputStream(FileOutputStream(archive.toFile())).use { ar ->
            val content = "hello ar".encodeToByteArray()
            ar.putArchiveEntry(ArArchiveEntry("readme.txt", content.size.toLong()))
            ar.write(content)
            ar.closeArchiveEntry()
        }
        val outputDir = tempDir.resolve("ar-out").toFile()

        extractSupportedArchive(archive.toFile(), outputDir)

        assertEquals(
            "hello ar",
            outputDir.resolve("readme.txt").readText()
        )
    }

    @Test
    fun `extractSupportedArchive rejects path traversal entries`() {
        val archive = tempDir.resolve("evil.zip")
        ZipOutputStream(FileOutputStream(archive.toFile())).use { zip ->
            zip.putNextEntry(ZipEntry("../escape.txt"))
            zip.write("nope".encodeToByteArray())
            zip.closeEntry()
        }
        val outputDir = tempDir.resolve("evil-out").toFile()

        val error = org.junit.jupiter.api.assertThrows<SecurityException> {
            extractSupportedArchive(archive.toFile(), outputDir)
        }

        assertTrue(error.message!!.contains("Path Traversal"))
    }
}
