package com.kyhsgeekcode.disassembler.ui.tabs

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class StringSearchInputPolicyTest {
    @Test
    fun `buildStringSearchInput uses full content when file is within limit`() {
        val input = buildStringSearchInput(
            previewBytes = "hello".encodeToByteArray(),
            originalSize = 5,
            maxBytes = 8
        )

        assertEquals("hello", input.bytes.decodeToString())
        assertFalse(input.isTruncated)
        assertEquals(5, input.originalSize)
    }

    @Test
    fun `buildStringSearchInput marks truncated scans when file exceeds limit`() {
        val input = buildStringSearchInput(
            previewBytes = "abcd".encodeToByteArray(),
            originalSize = 10,
            maxBytes = 4
        )

        assertEquals("abcd", input.bytes.decodeToString())
        assertTrue(input.isTruncated)
        assertEquals(10, input.originalSize)
    }

    @Test
    fun `buildStringSearchNotice describes bounded scans`() {
        assertEquals(
            "Searching strings in first 4 bytes of 10 bytes",
            buildStringSearchNotice(
                StringSearchInput(bytes = "abcd".encodeToByteArray(), originalSize = 10, isTruncated = true),
                resultsTruncated = false
            )
        )
    }

    @Test
    fun `buildStringSearchNotice combines scan and result truncation`() {
        assertEquals(
            "Searching strings in first 4 bytes of 10 bytes. Showing first 5000 results.",
            buildStringSearchNotice(
                StringSearchInput(bytes = "abcd".encodeToByteArray(), originalSize = 10, isTruncated = true),
                resultsTruncated = true
            )
        )
    }

    @Test
    fun `buildStringSearchDialogNotice is null for files within the search limit`() {
        assertEquals(
            null,
            buildStringSearchDialogNotice(
                originalSize = MAX_SEARCHED_STRING_BYTES.toLong(),
                maxBytes = MAX_SEARCHED_STRING_BYTES
            )
        )
    }

    @Test
    fun `buildStringSearchDialogNotice warns when only a prefix will be searched`() {
        assertEquals(
            "Large file detected. String search will only scan the first 4 bytes of 10 bytes.",
            buildStringSearchDialogNotice(
                originalSize = 10,
                maxBytes = 4
            )
        )
    }
}
