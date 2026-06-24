package com.kyhsgeekcode.disassembler.project

import java.nio.file.Files
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ProjectDataStorageCachePolicyTest {
    @Test
    fun `shouldCacheFileContent caches small files`() {
        assertTrue(shouldCacheFileContent(1024))
        assertTrue(shouldCacheFileContent(MAX_CACHED_FILE_CONTENT_BYTES))
    }

    @Test
    fun `shouldCacheFileContent skips large files`() {
        assertFalse(shouldCacheFileContent(MAX_CACHED_FILE_CONTENT_BYTES + 1L))
        assertFalse(shouldCacheFileContent(150L * 1024 * 1024))
    }

    @Test
    fun `readPreviewBytes returns full content when under limit`() {
        val file = createTempDirectory("project-data-storage").resolve("small.bin").toFile().apply {
            writeBytes(byteArrayOf(1, 2, 3, 4))
        }

        assertContentEquals(byteArrayOf(1, 2, 3, 4), readPreviewBytes(file, maxBytes = 8))
    }

    @Test
    fun `readPreviewBytes truncates content at limit`() {
        val file = createTempDirectory("project-data-storage").resolve("large.bin").toFile().apply {
            writeBytes(byteArrayOf(1, 2, 3, 4, 5, 6))
        }

        assertContentEquals(byteArrayOf(1, 2, 3, 4), readPreviewBytes(file, maxBytes = 4))
    }

    @Test
    fun `clear removes cached file content`() {
        ProjectDataStorage.data["sample" to DataType.FileContent] = byteArrayOf(1, 2, 3)

        ProjectDataStorage.clear()

        assertTrue(ProjectDataStorage.data.isEmpty())
    }
}
