package com.kyhsgeekcode

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ArchiveDetectionTest {
    @Test
    fun `isKnownArchiveExtension recognizes supported archive names`() {
        assertTrue(isKnownArchiveExtension("sample.zip"))
        assertTrue(isKnownArchiveExtension("sample.apk"))
        assertTrue(isKnownArchiveExtension("sample.jar"))
        assertTrue(isKnownArchiveExtension("sample.aar"))
        assertTrue(isKnownArchiveExtension("sample.ar"))
        assertTrue(isKnownArchiveExtension("sample.tar"))
    }

    @Test
    fun `isKnownArchiveExtension ignores non archive names`() {
        assertFalse(isKnownArchiveExtension("sample.dex"))
        assertFalse(isKnownArchiveExtension("sample.so"))
        assertFalse(isKnownArchiveExtension("sample"))
    }
}
