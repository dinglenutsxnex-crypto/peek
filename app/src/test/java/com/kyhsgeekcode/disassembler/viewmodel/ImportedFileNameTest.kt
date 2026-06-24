package com.kyhsgeekcode.disassembler.viewmodel

import java.io.File
import kotlin.io.path.createTempDirectory
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ImportedFileNameTest {
    @Test
    fun `sanitizeImportedFileName keeps a normal file name`() {
        assertEquals("sample.apk", sanitizeImportedFileName("sample.apk"))
    }

    @Test
    fun `sanitizeImportedFileName replaces path separators`() {
        assertEquals("folder_child.apk", sanitizeImportedFileName("folder/child.apk"))
        assertEquals("folder_child.apk", sanitizeImportedFileName("folder\\\\child.apk"))
    }

    @Test
    fun `sanitizeImportedFileName falls back when missing`() {
        assertEquals("openDirect", sanitizeImportedFileName(null))
        assertEquals("openDirect", sanitizeImportedFileName("   "))
    }

    @Test
    fun `resolveImportedDestinationFile keeps original file name when unused`() {
        val importsDir = createTempDirectory("imports-test").toFile()

        val destination = resolveImportedDestinationFile(importsDir, "sample.apk")

        assertEquals(File(importsDir, "sample.apk"), destination)
    }

    @Test
    fun `resolveImportedDestinationFile appends suffix when file name already exists`() {
        val importsDir = createTempDirectory("imports-test").toFile()
        File(importsDir, "sample.apk").writeText("existing")

        val destination = resolveImportedDestinationFile(importsDir, "sample.apk")

        assertEquals("sample_1.apk", destination.name)
        assertTrue(destination.parentFile == importsDir)
    }
}
