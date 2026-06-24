#pragma once

#include "disassembler.h"
#include <cstdint>
#include <string>
#include <vector>

enum class XrefType : uint8_t {
    CALL = 0,   // BL, BLR (direct only)
    BRANCH,     // B, B.cond, CBZ, CBNZ, TBZ, TBNZ
    DATA,       // ADRP+ADD or ADRP+LDR data reference
};

struct Xref {
    uint64_t from_address;
    uint64_t to_address;
    XrefType ref_type;
};

const char* xref_type_str(XrefType t);

// Detect direct xrefs from a list of already-disassembled instructions.
// `section_base` and `section_end` define the code section VA range used to
// validate that a branch target lands in code (code-to-code vs code-to-data).
std::vector<Xref> detect_xrefs(
    const std::vector<DisasmInstruction>& instructions,
    uint64_t section_base,
    uint64_t section_end
);
