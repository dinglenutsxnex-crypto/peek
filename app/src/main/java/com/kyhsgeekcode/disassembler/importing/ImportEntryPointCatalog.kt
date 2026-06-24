package com.kyhsgeekcode.disassembler.importing

import com.kyhsgeekcode.disassembler.storagePermissionsForSdk
import com.kyhsgeekcode.disassembler.R

sealed class ImportEntryPoint(val labelRes: Int) {
    object SafImport : ImportEntryPoint(R.string.select_file)
    object AdvancedImport : ImportEntryPoint(R.string.advanced_import)
}

interface ImportEntryPointCatalog {
    fun visibleEntryPoints(powerUserMode: Boolean): List<ImportEntryPoint>
}

object DefaultImportEntryPointCatalog : ImportEntryPointCatalog {
    override fun visibleEntryPoints(powerUserMode: Boolean): List<ImportEntryPoint> {
        return if (powerUserMode) {
            listOf(ImportEntryPoint.SafImport, ImportEntryPoint.AdvancedImport)
        } else {
            listOf(ImportEntryPoint.SafImport)
        }
    }
}

fun legacyPermissionsForImportEntryPoint(entryPoint: ImportEntryPoint, sdkInt: Int): Array<String> {
    return when (entryPoint) {
        ImportEntryPoint.SafImport -> emptyArray()
        ImportEntryPoint.AdvancedImport -> storagePermissionsForSdk(sdkInt)
    }
}
