package com.kyhsgeekcode.disassembler.ui.tabs

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class TextPreviewTest {
    @Test
    fun `buildTextContentPreview keeps short content unchanged`() {
        val preview = buildTextContentPreview("hello".encodeToByteArray(), maxBytes = 8)

        assertEquals("hello", preview.bytes.decodeToString())
        assertFalse(preview.isTruncated)
        assertEquals(5, preview.originalSize)
    }

    @Test
    fun `buildTextContentPreview truncates large content`() {
        val preview = buildTextContentPreview("abcdefghij".encodeToByteArray(), maxBytes = 4)

        assertEquals("abcd", preview.bytes.decodeToString())
        assertTrue(preview.isTruncated)
        assertEquals(10, preview.originalSize)
    }
}
