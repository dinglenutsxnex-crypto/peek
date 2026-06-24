package com.kyhsgeekcode.disassembler.exporting

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class BinaryDetailsExportTest {
    @Test
    fun `buildBinaryDetailsExportFileName uses source file name with details suffix`() {
        assertEquals(
            "libexample.so_details.txt",
            buildBinaryDetailsExportFileName("/tmp/libexample.so")
        )
    }

    @Test
    fun `buildBinaryDetailsExportFileName falls back when source path is missing`() {
        assertEquals(
            "details.txt",
            buildBinaryDetailsExportFileName("")
        )
    }

    @Test
    fun `buildBinaryDetailsExportFileName sanitizes invalid characters`() {
        assertEquals(
            "badnamedetails.bin_details.txt",
            buildBinaryDetailsExportFileName("/tmp/bad:name?details.bin")
        )
    }
}
