#pragma once

#include "elf_parser.h"
#include <cstdint>
#include <string>
#include <vector>

struct DisasmInstruction {
    uint64_t    address;
    uint32_t    size;           // bytes
    std::string bytes_hex;      // e.g. "1f2003d5"
    std::string mnemonic;
    std::string operands;
    uint32_t    function_id;    // set by caller after DB insert
};

struct DisasmResult {
    bool                          ok = false;
    std::string                   error;
    std::vector<DisasmInstruction> instructions;
};

// Disassemble bytes at virtual address `start_va` for `length` bytes.
// `data` must point to the raw bytes (file-mapped slice at that VA).
DisasmResult disassemble_arm64(
    const uint8_t* data,
    size_t         length,
    uint64_t       start_va
);
