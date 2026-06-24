package com.kyhsgeekcode.disassembler.importing

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class AdvancedImportSourceCatalogTest {
    @Test
    fun `power user disabled exposes no advanced sources`() {
        assertEquals(
            emptyList<AdvancedImportSource>(),
            DefaultAdvancedImportSourceCatalog.visibleSources(
                AdvancedImportOptions(
                    powerUserMode = false,
                    filesystemAccess = true,
                    installedAppsAccess = true,
                    researchToolsAccess = true
                )
            )
        )
    }

    @Test
    fun `power user mode exposes only enabled advanced source groups`() {
        assertEquals(
            listOf(
                AdvancedImportSource.Filesystem,
                AdvancedImportSource.ResearchTools
            ),
            DefaultAdvancedImportSourceCatalog.visibleSources(
                AdvancedImportOptions(
                    powerUserMode = true,
                    filesystemAccess = true,
                    installedAppsAccess = false,
                    researchToolsAccess = true
                )
            )
        )
    }
}
