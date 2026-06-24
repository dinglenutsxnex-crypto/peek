package com.kyhsgeekcode.disassembler.viewmodel

import com.kyhsgeekcode.disassembler.ui.TabData
import com.kyhsgeekcode.disassembler.ui.TabKind
import kotlin.test.Test
import kotlin.test.assertEquals

class OpenedProjectWorkspaceStateTest {
    @Test
    fun `openedProjectWorkspaceState resets tabs to overview`() {
        val previousTabs = listOf(
            TabData("Overview", TabKind.ProjectOverview),
            TabData("classes.dex as Binary", TabKind.Binary("classes.dex"))
        )

        val state = openedProjectWorkspaceState(previousTabs, previousCurrentTabIndex = 1)

        assertEquals(0, state.currentTabIndex)
        assertEquals(listOf(TabData("Overview", TabKind.ProjectOverview)), state.openedTabs)
    }
}
