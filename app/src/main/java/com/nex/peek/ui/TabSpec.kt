package com.nex.peek.ui

enum class TabId { ASM, HEX, EXPORTS, IMPORTS, PSEUDOCODE }

data class TabSpec(val id: TabId, val label: String)
