package com.kyhsgeekcode.disassembler.ui.tabs

import com.kyhsgeekcode.disassembler.FoundString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class StringSearchResultAccumulatorTest {
    @Test
    fun `accumulator keeps results under the limit`() {
        val accumulator = StringSearchResultAccumulator(maxResults = 2)

        accumulator.append(FoundString(offset = 1, string = "a"))
        accumulator.append(FoundString(offset = 2, string = "b"))

        assertEquals(
            listOf(
                FoundString(offset = 1, string = "a"),
                FoundString(offset = 2, string = "b")
            ),
            accumulator.results
        )
        assertFalse(accumulator.isTruncated)
    }

    @Test
    fun `accumulator truncates additional results`() {
        val accumulator = StringSearchResultAccumulator(maxResults = 2)

        accumulator.append(FoundString(offset = 1, string = "a"))
        accumulator.append(FoundString(offset = 2, string = "b"))
        accumulator.append(FoundString(offset = 3, string = "c"))

        assertEquals(2, accumulator.results.size)
        assertTrue(accumulator.isTruncated)
    }

    @Test
    fun `accumulator clips oversized string payloads for rendering`() {
        val accumulator = StringSearchResultAccumulator(maxResults = 2)

        accumulator.append(
            FoundString(
                offset = 1,
                length = 5_000,
                string = "A".repeat(5_000)
            )
        )

        assertTrue(accumulator.isTruncated)
        assertTrue(
            accumulator.results.single().string.length <= 4_096,
            "Large string payloads should be clipped before they reach the UI list"
        )
    }

    @Test
    fun `accumulator bounds total rendered string payload`() {
        val accumulator = StringSearchResultAccumulator(maxResults = 10)

        repeat(10) {
            accumulator.append(
                FoundString(
                    offset = it.toLong(),
                    length = 5_000,
                    string = "A".repeat(5_000)
                )
            )
        }

        assertTrue(accumulator.isTruncated)
        assertTrue(
            accumulator.results.sumOf { it.string.length } <= 32_768,
            "Large result sets should stop growing once the UI payload budget is exhausted"
        )
    }
}
