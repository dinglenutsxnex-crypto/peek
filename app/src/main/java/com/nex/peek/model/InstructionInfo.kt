package com.nex.peek.model

data class InstructionInfo(
    val address: ULong,
    val size: Int,
    val bytesHex: String,
    val mnemonic: String,
    val operands: String
) {
    val addressHex: String
        get() = address.toString(16).uppercase().padStart(8, '0')

    val bytesFormatted: String
        get() = bytesHex.chunked(2).joinToString(" ")

    val fullText: String
        get() = if (operands.isEmpty()) mnemonic else "$mnemonic $operands"
}
