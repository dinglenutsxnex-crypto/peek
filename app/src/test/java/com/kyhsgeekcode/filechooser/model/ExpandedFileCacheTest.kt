package com.kyhsgeekcode.filechooser.model

import java.io.ByteArrayInputStream
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class ExpandedFileCacheTest {
    @Test
    fun `buildExpandedFileCacheKey is stable for equal content`() {
        val first = buildExpandedFileCacheKey(ByteArrayInputStream("same-content".encodeToByteArray()))
        val second = buildExpandedFileCacheKey(ByteArrayInputStream("same-content".encodeToByteArray()))

        assertEquals(first, second)
    }

    @Test
    fun `buildExpandedFileCacheKey changes for different content`() {
        val first = buildExpandedFileCacheKey(ByteArrayInputStream("same-content".encodeToByteArray()))
        val second = buildExpandedFileCacheKey(ByteArrayInputStream("different-content".encodeToByteArray()))

        assertNotEquals(first, second)
    }

    @Test
    fun `buildExpandedFileCacheKeyFromFile matches stream key`() {
        val tempFile = File.createTempFile("expanded-cache", ".bin").apply {
            writeBytes("file-content".encodeToByteArray())
            deleteOnExit()
        }

        val streamKey = buildExpandedFileCacheKey(ByteArrayInputStream("file-content".encodeToByteArray()))
        val fileKey = buildExpandedFileCacheKey(tempFile)

        assertEquals(streamKey, fileKey)
    }
}
