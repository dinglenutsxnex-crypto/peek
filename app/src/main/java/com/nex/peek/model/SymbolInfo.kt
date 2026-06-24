package com.nex.peek.model

data class SymbolInfo(
    val address: ULong,
    val name: String,
    val typeStr: String,
    val isImport: Boolean
) {
    val addressHex: String
        get() = "0x${address.toString(16).uppercase().padStart(8, '0')}"

    val badge: String
        get() = if (isImport) "IMP" else "EXP"
}
