package com.kyhsgeekcode.disassembler

import android.content.ComponentName
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.espresso.intent.Intents.intending
import androidx.test.espresso.intent.matcher.IntentMatchers.hasComponent
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.kyhsgeekcode.disassembler.project.models.ProjectType
import com.kyhsgeekcode.disassembler.ui.MainTestTags
import com.kyhsgeekcode.filechooser.NewFileChooserActivity
import org.junit.Rule
import org.junit.Test
import org.junit.rules.RuleChain
import org.junit.runner.RunWith
import androidx.test.core.app.ApplicationProvider
import android.content.Context

@RunWith(AndroidJUnit4::class)
class MainActivityAdvancedImportFlowTest {
    companion object {
        private const val PROJECT_OPEN_TIMEOUT_MS = 15_000L
    }

    private val projectCleanupRule = ProjectStateCleanupRule()
    private val preferenceRule = PowerUserModePreferenceRule(powerUserModeEnabled = true)
    private val intentsRule = InstrumentationIntentsRule()
    private val composeRule = createAndroidComposeRule<MainActivity>()

    @get:Rule
    val rules: RuleChain = RuleChain.outerRule(projectCleanupRule)
        .around(preferenceRule)
        .around(intentsRule)
        .around(composeRule)

    @Test
    fun advancedImportResult_opensProjectAndShowsExportButton() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val importedFile = context.filesDir.resolve("androidTest/advanced/sample.so")
        importedFile.parentFile?.mkdirs()
        importedFile.writeBytes("so-data".encodeToByteArray())

        intending(
            hasComponent(
                ComponentName(
                    composeRule.activity,
                    NewFileChooserActivity::class.java
                )
            )
        ).respondWith(
            createAdvancedImportResultForFile(
                file = importedFile,
                openProject = false,
                projectType = ProjectType.UNKNOWN
            )
        )

        composeRule.onNodeWithTag(MainTestTags.IMPORT_ADVANCED_BUTTON).performClick()

        composeRule.onNodeWithTag(MainTestTags.COPY_DIALOG_YES_BUTTON).performClick()

        composeRule.waitUntil(timeoutMillis = PROJECT_OPEN_TIMEOUT_MS) {
            composeRule.onAllNodesWithTag(MainTestTags.EXPORT_PROJECT_BUTTON)
                .fetchSemanticsNodes().isNotEmpty()
        }
    }

    @Test
    fun advancedImportResult_copyNo_opensProjectAndSurvivesRecreate() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val importedFile = context.filesDir.resolve("androidTest/advanced/sample-no-copy.so")
        importedFile.parentFile?.mkdirs()
        importedFile.writeBytes("so-data".encodeToByteArray())

        intending(
            hasComponent(
                ComponentName(
                    composeRule.activity,
                    NewFileChooserActivity::class.java
                )
            )
        ).respondWith(
            createAdvancedImportResultForFile(
                file = importedFile,
                openProject = false,
                projectType = ProjectType.UNKNOWN
            )
        )

        composeRule.onNodeWithTag(MainTestTags.IMPORT_ADVANCED_BUTTON).performClick()
        composeRule.onNodeWithTag(MainTestTags.COPY_DIALOG_NO_BUTTON).performClick()

        waitForProjectOpen()
        composeRule.activityRule.scenario.recreate()
        waitForProjectOpen()
        composeRule.onNodeWithTag(MainTestTags.EXPORT_PROJECT_BUTTON).assertExists()
    }

    @Test
    fun advancedImportOpenProjectResult_importsProjectArchive() {
        val archiveFile = createProjectArchiveFixture()

        intending(
            hasComponent(
                ComponentName(
                    composeRule.activity,
                    NewFileChooserActivity::class.java
                )
            )
        ).respondWith(
            createAdvancedImportResultForFile(
                file = archiveFile,
                openProject = true,
                projectType = ProjectType.UNKNOWN
            )
        )

        composeRule.onNodeWithTag(MainTestTags.IMPORT_ADVANCED_BUTTON).performClick()

        composeRule.waitUntil(timeoutMillis = PROJECT_OPEN_TIMEOUT_MS) {
            composeRule.onAllNodesWithTag(MainTestTags.EXPORT_PROJECT_BUTTON)
                .fetchSemanticsNodes().isNotEmpty()
        }
    }

    private fun waitForProjectOpen() {
        composeRule.waitUntil(timeoutMillis = PROJECT_OPEN_TIMEOUT_MS) {
            composeRule.onAllNodesWithTag(MainTestTags.EXPORT_PROJECT_BUTTON)
                .fetchSemanticsNodes().isNotEmpty()
        }
    }
}
