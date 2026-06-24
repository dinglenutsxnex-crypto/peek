package com.kyhsgeekcode.disassembler

import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

@OptIn(ExperimentalUnsignedTypes::class)
class AnalyzerStringSearchTest {
    @Test
    fun `searchStrings clips oversized string matches before emitting them`() {
        val analyzer = Analyzer(ByteArray(2 * 1024 * 1024) { 'A'.code.toByte() } + byteArrayOf(0))
        var foundString: FoundString? = null

        analyzer.searchStrings(1, Int.MAX_VALUE) { _, _, result ->
            if (result != null) {
                foundString = result
            }
        }

        assertNotNull(foundString)
        assertTrue(
            foundString!!.string.length <= 4_096,
            "Analyzer should not allocate oversized string matches before handing them to the UI layer"
        )
    }
}
