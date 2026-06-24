package com.nex.peek.model

data class XrefInfo(
    val fromAddress: ULong,
    val toAddress: ULong,
    val refType: String
) {
    val fromHex: String get() = "0x${fromAddress.toString(16).uppercase().padStart(8, '0')}"
    val toHex:   String get() = "0x${toAddress.toString(16).uppercase().padStart(8, '0')}"
    val typeLabel: String get() = refType.uppercase()
}
