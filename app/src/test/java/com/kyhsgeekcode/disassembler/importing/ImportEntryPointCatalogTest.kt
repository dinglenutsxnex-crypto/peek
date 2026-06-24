package com.kyhsgeekcode.disassembler.importing

import android.Manifest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class ImportEntryPointCatalogTest {
    @Test
    fun `standard mode only exposes SAF import`() {
        assertEquals(
            listOf(ImportEntryPoint.SafImport),
            DefaultImportEntryPointCatalog.visibleEntryPoints(powerUserMode = false)
        )
    }

    @Test
    fun `power user mode exposes SAF and advanced import`() {
        assertEquals(
            listOf(ImportEntryPoint.SafImport, ImportEntryPoint.AdvancedImport),
            DefaultImportEntryPointCatalog.visibleEntryPoints(powerUserMode = true)
        )
    }

    @Test
    fun `SAF import requires no legacy storage permissions on any supported SDK`() {
        assertEquals(emptyArray<String>().toList(), legacyPermissionsForImportEntryPoint(ImportEntryPoint.SafImport, 28).toList())
        assertEquals(emptyArray<String>().toList(), legacyPermissionsForImportEntryPoint(ImportEntryPoint.SafImport, 35).toList())
    }

    @Test
    fun `advanced import requires legacy storage permissions only on Android 9 and below`() {
        assertEquals(
            listOf(
                Manifest.permission.READ_EXTERNAL_STORAGE,
                Manifest.permission.WRITE_EXTERNAL_STORAGE
            ),
            legacyPermissionsForImportEntryPoint(ImportEntryPoint.AdvancedImport, 28).toList()
        )
        assertEquals(emptyArray<String>().toList(), legacyPermissionsForImportEntryPoint(ImportEntryPoint.AdvancedImport, 29).toList())
        assertEquals(emptyArray<String>().toList(), legacyPermissionsForImportEntryPoint(ImportEntryPoint.AdvancedImport, 35).toList())
    }
}
