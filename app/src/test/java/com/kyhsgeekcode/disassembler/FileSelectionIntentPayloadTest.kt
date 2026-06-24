package com.kyhsgeekcode.disassembler

import com.kyhsgeekcode.disassembler.project.models.ProjectType
import com.kyhsgeekcode.disassembler.viewmodel.selectedFileIntentPayload
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class FileSelectionIntentPayloadTest {
    @Test
    fun `selectedFileIntentPayload reads compact chooser extras`() {
        val payload = selectedFileIntentPayload(
            filePath = "/tmp/sample.apk",
            nativeFilePath = "/tmp/lib",
            projectType = ProjectType.APK
        )

        requireNotNull(payload)
        assertEquals("/tmp/sample.apk", payload.filePath)
        assertEquals("/tmp/lib", payload.nativeFilePath)
        assertEquals(ProjectType.APK, payload.projectType)
    }

    @Test
    fun `selectedFileIntentPayload returns null when chooser file path is missing`() {
        assertNull(
            selectedFileIntentPayload(
                filePath = null,
                nativeFilePath = null,
                projectType = ProjectType.UNKNOWN
            )
        )
    }
}
