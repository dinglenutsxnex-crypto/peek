package com.kyhsgeekcode.disassembler

import androidx.compose.ui.test.junit4.AndroidComposeTestRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.ext.junit.rules.ActivityScenarioRule
import com.kyhsgeekcode.disassembler.ui.MainTestTags
import org.junit.Rule
import org.junit.Test
import org.junit.rules.RuleChain
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MainActivityExtraStreamIntentFlowTest {
    companion object {
        private const val PROJECT_OPEN_TIMEOUT_MS = 10_000L
    }

    private val projectCleanupRule = ProjectStateCleanupRule()
    private val activityRule = ActivityScenarioRule<MainActivity>(
        createExtraStreamIntent(
            displayName = "incoming-stream.apk",
            content = "incoming-stream-content".encodeToByteArray()
        )
    )
    private val composeRule = AndroidComposeTestRule<ActivityScenarioRule<MainActivity>, MainActivity>(
        activityRule
    ) { rule: ActivityScenarioRule<MainActivity> ->
        var activity: MainActivity? = null
        rule.scenario.onActivity { activity = it }
        checkNotNull(activity)
    }

    @get:Rule
    val rules: RuleChain = RuleChain.outerRule(projectCleanupRule)
        .around(composeRule)

    @Test
    fun extraStreamContentUri_opensProject() {
        waitForProjectOpen()
        composeRule.onNodeWithTag(MainTestTags.EXPORT_PROJECT_BUTTON).assertExists()
    }

    @Test
    fun extraStreamContentUri_survivesRecreate() {
        waitForProjectOpen()
        composeRule.activityRule.scenario.recreate()
        waitForProjectOpen()
        composeRule.onNodeWithTag(MainTestTags.EXPORT_PROJECT_BUTTON).assertExists()
    }

    private fun waitForProjectOpen() {
        composeRule.waitUntil(timeoutMillis = PROJECT_OPEN_TIMEOUT_MS) {
            composeRule.onAllNodesWithTag(MainTestTags.EXPORT_PROJECT_BUTTON)
                .fetchSemanticsNodes().isNotEmpty()
        }
    }
}
