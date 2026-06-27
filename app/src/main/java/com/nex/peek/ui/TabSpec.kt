package com.nex.peek.ui

enum class TabId { ASM, HEX, EXPORTS, IMPORTS }

data class TabSpec(val id: TabId, val label: String)
