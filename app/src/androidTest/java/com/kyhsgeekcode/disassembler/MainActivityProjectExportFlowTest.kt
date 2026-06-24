package com.kyhsgeekcode.disassembler

import android.content.Intent
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.espresso.intent.Intents.intending
import androidx.test.espresso.intent.matcher.IntentMatchers.hasAction
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.kyhsgeekcode.disassembler.ui.MainTestTags
import org.hamcrest.CoreMatchers.allOf
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.RuleChain
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MainActivityProjectExportFlowTest {
    private val projectCleanupRule = ProjectStateCleanupRule()
    private val preferenceRule = PowerUserModePreferenceRule(powerUserModeEnabled = false)
    private val intentsRule = InstrumentationIntentsRule()
    private val composeRule = createAndroidComposeRule<MainActivity>()

    @get:Rule
    val rules: RuleChain = RuleChain.outerRule(projectCleanupRule)
        .around(preferenceRule)
        .around(intentsRule)
        .around(composeRule)

    @Test
    fun exportProjectResult_writesZipDocument() {
        intending(
            allOf(
                hasAction(Intent.ACTION_OPEN_DOCUMENT)
            )
        ).respondWith(
            createOpenDocumentResult(
                displayName = "export-source.apk",
                content = "export-content".encodeToByteArray()
            )
        )
        val (outputFile, createDocumentResult) = createCreateDocumentResult("project-export.zip")
        intending(
            allOf(
                hasAction(Intent.ACTION_CREATE_DOCUMENT)
            )
        ).respondWith(createDocumentResult)

        composeRule.onNodeWithTag(MainTestTags.IMPORT_SAF_BUTTON).performClick()
        composeRule.waitUntil(timeoutMillis = 5_000) {
            composeRule.onAllNodesWithTag(MainTestTags.EXPORT_PROJECT_BUTTON)
                .fetchSemanticsNodes().isNotEmpty()
        }

        composeRule.onNodeWithTag(MainTestTags.EXPORT_PROJECT_BUTTON).performClick()

        composeRule.waitUntil(timeoutMillis = 5_000) {
            outputFile.length() > 0L
        }

        assertTrue(outputFile.readBytes().size > 4)
        assertTrue(outputFile.readText(Charsets.ISO_8859_1).startsWith("PK"))
    }

    @Test
    fun exportProjectCancel_keepsProjectOpen() {
        intending(
            allOf(
                hasAction(Intent.ACTION_OPEN_DOCUMENT)
            )
        ).respondWith(
            createOpenDocumentResult(
                displayName = "export-cancel-source.apk",
                content = "export-content".encodeToByteArray()
            )
        )
        intending(
            allOf(
                hasAction(Intent.ACTION_CREATE_DOCUMENT)
            )
        ).respondWith(createCanceledActivityResult())

        composeRule.onNodeWithTag(MainTestTags.IMPORT_SAF_BUTTON).performClick()
        waitForProjectOpen()

        composeRule.onNodeWithTag(MainTestTags.EXPORT_PROJECT_BUTTON).performClick()
        composeRule.waitForIdle()
        composeRule.onNodeWithTag(MainTestTags.EXPORT_PROJECT_BUTTON).assertExists()
    }

    private fun waitForProjectOpen() {
        composeRule.waitUntil(timeoutMillis = 5_000) {
            composeRule.onAllNodesWithTag(MainTestTags.EXPORT_PROJECT_BUTTON)
                .fetchSemanticsNodes().isNotEmpty()
        }
    }
}
