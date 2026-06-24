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
import org.junit.Rule
import org.junit.Test
import org.junit.rules.RuleChain
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MainActivitySafImportFlowTest {
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
    fun safImportResult_opensProjectAndShowsExportButton() {
        intending(
            allOf(
                hasAction(Intent.ACTION_OPEN_DOCUMENT)
            )
        ).respondWith(
            createOpenDocumentResult(
                displayName = "sample.apk",
                content = "apk-content".encodeToByteArray()
            )
        )

        composeRule.onNodeWithTag(MainTestTags.IMPORT_SAF_BUTTON).performClick()

        composeRule.waitUntil(timeoutMillis = 5_000) {
            composeRule.onAllNodesWithTag(MainTestTags.EXPORT_PROJECT_BUTTON)
                .fetchSemanticsNodes().isNotEmpty()
        }

        composeRule.onNodeWithTag(MainTestTags.EXPORT_PROJECT_BUTTON).assertExists()
    }

    @Test
    fun safImportResult_survivesRecreate() {
        intending(
            allOf(
                hasAction(Intent.ACTION_OPEN_DOCUMENT)
            )
        ).respondWith(
            createOpenDocumentResult(
                displayName = "sample-recreate.apk",
                content = "apk-content".encodeToByteArray()
            )
        )

        composeRule.onNodeWithTag(MainTestTags.IMPORT_SAF_BUTTON).performClick()

        waitForProjectOpen()
        composeRule.activityRule.scenario.recreate()
        waitForProjectOpen()
        composeRule.onNodeWithTag(MainTestTags.EXPORT_PROJECT_BUTTON).assertExists()
    }

    private fun waitForProjectOpen() {
        composeRule.waitUntil(timeoutMillis = 5_000) {
            composeRule.onAllNodesWithTag(MainTestTags.EXPORT_PROJECT_BUTTON)
                .fetchSemanticsNodes().isNotEmpty()
        }
    }
}
