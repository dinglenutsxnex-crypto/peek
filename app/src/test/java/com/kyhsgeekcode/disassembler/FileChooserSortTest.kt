package com.kyhsgeekcode.disassembler

import com.kyhsgeekcode.filechooser.fileItemSortGroup
import com.kyhsgeekcode.filechooser.sortableFileItemText
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class FileChooserSortTest {
    @Test
    fun `sortableFileItemText tolerates empty labels`() {
        val sorted = listOf("", "beta", "alpha").sortedWith(
            compareBy(
                ::fileItemSortGroup,
                ::sortableFileItemText
            )
        )

        assertEquals(listOf("", "alpha", "beta"), sorted)
    }

    @Test
    fun `fileItemSortGroup keeps folders ahead of files`() {
        val sorted = listOf("zeta", "alpha/", "beta").sortedWith(
            compareBy(
                ::fileItemSortGroup,
                ::sortableFileItemText
            )
        )

        assertEquals(listOf("alpha/", "beta", "zeta"), sorted)
    }
}
