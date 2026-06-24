package com.kyhsgeekcode.disassembler.ui.tabs

import nl.lxtreme.binutils.elf.MachineType
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class BinaryManualSetupConfigTest {
    @Test
    fun `requiresDisassemblyReload is false when config is unchanged`() {
        val before = BinaryManualSetupConfig(
            codeSectionBase = 0x10,
            codeSectionLimit = 0x20,
            entryPoint = 0x12,
            codeVirtAddr = 0x1000,
            machineType = MachineType.i386
        )

        assertFalse(requiresDisassemblyReload(before, before.copy()))
    }

    @Test
    fun `requiresDisassemblyReload is true when any setup field changes`() {
        val before = BinaryManualSetupConfig(
            codeSectionBase = 0x10,
            codeSectionLimit = 0x20,
            entryPoint = 0x12,
            codeVirtAddr = 0x1000,
            machineType = MachineType.i386
        )

        assertTrue(requiresDisassemblyReload(before, before.copy(machineType = MachineType.x86_64)))
        assertTrue(requiresDisassemblyReload(before, before.copy(codeSectionBase = 0x11)))
        assertTrue(requiresDisassemblyReload(before, before.copy(codeSectionLimit = 0x21)))
        assertTrue(requiresDisassemblyReload(before, before.copy(entryPoint = 0x13)))
        assertTrue(requiresDisassemblyReload(before, before.copy(codeVirtAddr = 0x2000)))
    }
}
