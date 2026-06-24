package com.kyhsgeekcode.disassembler

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class MainActivityIntentHandlingTest {
    @Test
    fun `shouldHandleIncomingIntent handles external view intents on first create`() {
        assertTrue(shouldHandleIncomingIntent(hasIncomingIntent = true, hasSavedState = false))
    }

    @Test
    fun `shouldHandleIncomingIntent skips external view intents after recreation`() {
        assertFalse(shouldHandleIncomingIntent(hasIncomingIntent = true, hasSavedState = true))
    }

    @Test
    fun `shouldHandleIncomingIntent ignores launcher intents without imported content`() {
        assertFalse(shouldHandleIncomingIntent(hasIncomingIntent = false, hasSavedState = false))
    }
}
