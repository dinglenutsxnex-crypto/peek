package com.kyhsgeekcode.disassembler.models

import nl.lxtreme.binutils.elf.MachineType
import kotlin.test.Test
import kotlin.test.assertContentEquals

class ArchitectureTest {
    @Test
    fun `x86_64 maps to x86 64-bit mode`() {
        assertContentEquals(
            intArrayOf(Architecture.CS_ARCH_X86, Architecture.CS_MODE_64),
            Architecture.getArchitecture(MachineType.x86_64)
        )
    }

    @Test
    fun `ppc64 maps to ppc 64-bit mode`() {
        assertContentEquals(
            intArrayOf(Architecture.CS_ARCH_PPC, Architecture.CS_MODE_64),
            Architecture.getArchitecture(MachineType.PPC64)
        )
    }
}
