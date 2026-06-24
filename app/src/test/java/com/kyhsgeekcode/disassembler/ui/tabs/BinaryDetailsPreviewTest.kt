package com.kyhsgeekcode.disassembler.ui.tabs

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class BinaryDetailsPreviewTest {
    @Test
    fun `preview keeps short details unchanged`() {
        val preview = buildBinaryDetailsPreview("short text", maxChars = 32)

        assertEquals("short text", preview.text)
        assertFalse(preview.isTruncated)
    }

    @Test
    fun `preview truncates long details and adds notice`() {
        val preview = buildBinaryDetailsPreview("abcdefghijklmnopqrstuvwxyz", maxChars = 10)

        assertTrue(preview.isTruncated)
        assertEquals(
            "abcdefghij\n\n[Preview truncated. Use Save details to export the full text.]",
            preview.text
        )
    }
}
