package com.nex.peek.model

data class FunctionInfo(
    val id: Long,
    val address: ULong,
    val size: ULong,
    val name: String,
    val kind: Int = 1   // 0=local(sub_), 1=named, 2=thunk(j_)
) {
    val displayName: String
        get() = name.ifEmpty { "sub_${address.toString(16).uppercase()}" }

    val addressHex: String
        get() = "0x${address.toString(16).uppercase().padStart(8, '0')}"
}
