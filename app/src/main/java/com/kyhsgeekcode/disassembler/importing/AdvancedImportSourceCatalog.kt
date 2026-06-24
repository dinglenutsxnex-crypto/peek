package com.kyhsgeekcode.disassembler.importing

enum class AdvancedImportSource {
    Filesystem,
    InstalledApps,
    ResearchTools
}

data class AdvancedImportOptions(
    val powerUserMode: Boolean,
    val filesystemAccess: Boolean,
    val installedAppsAccess: Boolean,
    val researchToolsAccess: Boolean
)

interface AdvancedImportSourceCatalog {
    fun visibleSources(options: AdvancedImportOptions): List<AdvancedImportSource>
}

object DefaultAdvancedImportSourceCatalog : AdvancedImportSourceCatalog {
    override fun visibleSources(options: AdvancedImportOptions): List<AdvancedImportSource> {
        if (!options.powerUserMode) {
            return emptyList()
        }

        val visible = mutableListOf<AdvancedImportSource>()
        if (options.filesystemAccess) {
            visible += AdvancedImportSource.Filesystem
        }
        if (options.installedAppsAccess) {
            visible += AdvancedImportSource.InstalledApps
        }
        if (options.researchToolsAccess) {
            visible += AdvancedImportSource.ResearchTools
        }
        return visible
    }
}
