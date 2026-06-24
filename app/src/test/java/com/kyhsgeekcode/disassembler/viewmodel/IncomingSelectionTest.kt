package com.kyhsgeekcode.disassembler.viewmodel

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class IncomingSelectionTest {
    @Test
    fun `resolveIncomingSelection prefers compact chooser payload`() {
        val selection = resolveIncomingSelection(
            openAsProject = true,
            filePath = "/tmp/sample.apk",
            nativeFilePath = "/tmp/lib",
            projectType = "APK",
            uri = null,
            extraStreamUri = null,
            displayName = null
        )

        require(selection is IncomingSelection.CompactFile)
        assertEquals(true, selection.openAsProject)
        assertEquals("/tmp/sample.apk", selection.payload.filePath)
        assertEquals("/tmp/lib", selection.payload.nativeFilePath)
        assertEquals("APK", selection.payload.projectType)
    }

    @Test
    fun `resolveIncomingSelection ignores legacy serializable fileItem extras`() {
        assertNull(
            resolveIncomingSelection(
                openAsProject = false,
                filePath = null,
                nativeFilePath = null,
                projectType = null,
                uri = null,
                extraStreamUri = null,
                displayName = null
            )
        )
    }
}
