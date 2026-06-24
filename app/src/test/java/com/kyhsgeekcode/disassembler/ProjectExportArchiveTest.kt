package com.kyhsgeekcode.disassembler

import com.kyhsgeekcode.saveAsZip
import com.kyhsgeekcode.disassembler.exporting.buildProjectExportFileName
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.nio.file.Path
import java.util.zip.ZipFile

class ProjectExportArchiveTest {
    @TempDir
    lateinit var tempDir: Path

    @Test
    fun `saveAsZip packages project directories under relative prefixes`() {
        val sourceFile = tempDir.resolve("sample.apk").toFile().apply {
            writeText("source")
        }
        val generatedDir = tempDir.resolve("generated").toFile().apply {
            resolve("nested").mkdirs()
            resolve("nested").resolve("report.txt").writeText("generated")
        }
        val archive = tempDir.resolve("project.zip").toFile()

        saveAsZip(
            archive,
            sourceFile.path to "sourceFilePath",
            generatedDir.path to "baseFolder"
        )

        ZipFile(archive).use { zipFile ->
            assertNotNull(zipFile.getEntry("sourceFilePath"))
            assertNotNull(zipFile.getEntry("baseFolder/nested/report.txt"))
        }
    }

    @Test
    fun `saveAsZip does not leak absolute filesystem paths into archive entries`() {
        val sourceDir = tempDir.resolve("original").toFile().apply {
            resolve("nested").mkdirs()
            resolve("nested").resolve("classes.dex").writeText("dex")
        }
        val archive = tempDir.resolve("project.zip").toFile()

        saveAsZip(archive, sourceDir.path to "sourceFilePath")

        ZipFile(archive).use { zipFile ->
            val entryNames = zipFile.entries().asSequence().map { it.name }.toList()

            assertFalse(entryNames.any { it.startsWith(File.separator) })
            assertFalse(entryNames.any { it.contains(tempDir.toFile().absolutePath) })
        }
    }

    @Test
    fun `buildProjectExportFileName sanitizes invalid file name characters`() {
        val fileName = buildProjectExportFileName("bad:name/for*zip")

        org.junit.jupiter.api.Assertions.assertEquals(
            "DisassemblerProject_badnameforzip.zip",
            fileName
        )
    }
}
