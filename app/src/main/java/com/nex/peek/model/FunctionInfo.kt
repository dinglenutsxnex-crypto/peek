package com.nex.peek.model

data class FunctionInfo(
    val id: Long,
    val address: ULong,
    val size: ULong,
    val name: String
) {
    val displayName: String
        get() = name.ifEmpty { "sub_${address.toString(16).uppercase()}" }

    val addressHex: String
        get() = "0x${address.toString(16).uppercase().padStart(8, '0')}"
}
