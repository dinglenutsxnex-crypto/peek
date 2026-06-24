package com.kyhsgeekcode.disassembler

import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import com.kyhsgeekcode.disassembler.ui.MainTestTags
import org.junit.Rule
import org.junit.Test
import org.junit.rules.RuleChain

class MainActivityImportEntryPointStandardModeTest {
    private val preferenceRule = PowerUserModePreferenceRule(powerUserModeEnabled = false)
    private val composeRule = createAndroidComposeRule<MainActivity>()

    @get:Rule
    val rules: RuleChain = RuleChain.outerRule(preferenceRule).around(composeRule)

    @Test
    fun standardMode_showsSafImportOnly() {
        composeRule.onNodeWithTag(MainTestTags.IMPORT_SAF_BUTTON).assertExists()
        composeRule.onNodeWithTag(MainTestTags.IMPORT_ADVANCED_BUTTON).assertDoesNotExist()
    }
}
