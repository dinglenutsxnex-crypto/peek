#include "xref_detector.h"

#include <android/log.h>
#include <cstring>
#include <unordered_map>

#define TAG "PeekXref"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)

const char* xref_type_str(XrefType t) {
    switch (t) {
        case XrefType::CALL:   return "call";
        case XrefType::BRANCH: return "branch";
        case XrefType::DATA:   return "data";
    }
    return "unknown";
}

// ---------------------------------------------------------------------------
// ARM64 instruction decoding helpers
// ARM64 is fixed-width 32-bit little-endian instructions.
// ---------------------------------------------------------------------------

// B (unconditional): encoding 000101 imm26
static bool is_b(uint32_t insn, int64_t& imm26_out) {
    if ((insn >> 26) == 0x05) {
        int32_t imm = (int32_t)((insn & 0x3FFFFFF) << 6) >> 6; // sign-extend 26-bit
        imm26_out = (int64_t)imm * 4;
        return true;
    }
    return false;
}

// BL (branch-and-link): encoding 100101 imm26
static bool is_bl(uint32_t insn, int64_t& imm26_out) {
    if ((insn >> 26) == 0x25) {
        int32_t imm = (int32_t)((insn & 0x3FFFFFF) << 6) >> 6;
        imm26_out = (int64_t)imm * 4;
        return true;
    }
    return false;
}

// B.cond: encoding 01010100 imm19 0 cond
static bool is_bcond(uint32_t insn, int64_t& imm19_out) {
    if ((insn >> 24) == 0x54 && (insn & (1 << 4)) == 0) {
        int32_t imm = (int32_t)(((insn >> 5) & 0x7FFFF) << 13) >> 13;
        imm19_out = (int64_t)imm * 4;
        return true;
    }
    return false;
}

// CBZ/CBNZ: sf 011010 op imm19 Rt
static bool is_cbz_cbnz(uint32_t insn, int64_t& imm19_out) {
    uint32_t masked = insn & 0x7E000000;
    if (masked == 0x34000000 || masked == 0x35000000 || // 32-bit
        masked == 0xB4000000 || masked == 0xB5000000) { // 64-bit
        int32_t imm = (int32_t)(((insn >> 5) & 0x7FFFF) << 13) >> 13;
        imm19_out = (int64_t)imm * 4;
        return true;
    }
    return false;
}

// TBZ/TBNZ: b5 011011 b40 imm14 Rt
static bool is_tbz_tbnz(uint32_t insn, int64_t& imm14_out) {
    uint32_t masked = insn & 0x7E000000;
    if (masked == 0x36000000 || masked == 0x37000000 ||
        masked == 0xB6000000 || masked == 0xB7000000) {
        int32_t imm = (int32_t)(((insn >> 5) & 0x3FFF) << 18) >> 18;
        imm14_out = (int64_t)imm * 4;
        return true;
    }
    return false;
}

// ADRP: 1 immhi:2 10000 immlo:19 Rd
static bool is_adrp(uint32_t insn, int64_t& page_offset_out, uint8_t& rd_out) {
    if ((insn & 0x9F000000) == 0x90000000) {
        rd_out = insn & 0x1F;
        uint32_t immlo = (insn >> 29) & 3;
        int32_t  immhi = (int32_t)(((insn >> 5) & 0x7FFFF) << 13) >> 13;
        page_offset_out = ((int64_t)immhi << 14) | ((int64_t)immlo << 12);
        return true;
    }
    return false;
}

// ADD Rd, Rn, #imm12: sf 0010001 shift imm12 Rn Rd
static bool is_add_imm(uint32_t insn, uint8_t& rn_out, uint8_t& rd_out, int64_t& imm_out) {
    if ((insn & 0x7F800000) == 0x11000000 ||
        (insn & 0x7F800000) == 0x91000000) {
        rd_out  = insn & 0x1F;
        rn_out  = (insn >> 5) & 0x1F;
        int32_t imm = (insn >> 10) & 0xFFF;
        int32_t shift = (insn >> 22) & 3;
        imm_out = (shift == 1) ? ((int64_t)imm << 12) : (int64_t)imm;
        return true;
    }
    return false;
}

// LDR Rt, [Rn, #imm12]: 1x111001 01 imm12 Rn Rt  (unsigned offset)
static bool is_ldr_imm(uint32_t insn, uint8_t& rn_out) {
    // 64-bit: 1111 1001 01xx xxxx xxxx xxxx xxxx xxxx
    // 32-bit: 1011 1001 01xx xxxx xxxx xxxx xxxx xxxx
    if ((insn & 0xBFC00000) == 0xB9400000 ||
        (insn & 0xFFC00000) == 0xF9400000) {
        rn_out = (insn >> 5) & 0x1F;
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Main xref detection
// ---------------------------------------------------------------------------

std::vector<Xref> detect_xrefs(
    const std::vector<DisasmInstruction>& instructions,
    uint64_t section_base,
    uint64_t section_end)
{
    std::vector<Xref> xrefs;

    // Track ADRP targets per register for ADRP+ADD/LDR pairing
    // key = register index (0-30), value = computed page address
    uint64_t adrp_page[32] = {};
    bool     adrp_valid[32] = {};

    for (const auto& di : instructions) {
        uint64_t pc = di.address;

        // We re-decode from the mnemonic string for simplicity, but also
        // have the raw bytes for precise decoding.
        if (di.size != 4) continue; // ARM64 is always 4 bytes

        // Decode raw instruction word (little-endian)
        uint32_t word = 0;
        if (di.bytes_hex.size() >= 8) {
            for (int i = 0; i < 4; ++i) {
                uint8_t byte = (uint8_t)strtoul(di.bytes_hex.substr(i*2, 2).c_str(), nullptr, 16);
                word |= ((uint32_t)byte) << (i * 8);
            }
        }

        int64_t imm = 0;

        // BL → CALL xref
        if (is_bl(word, imm)) {
            uint64_t target = pc + (uint64_t)imm;
            xrefs.push_back({pc, target, XrefType::CALL});
            memset(adrp_valid, 0, sizeof(adrp_valid));
            continue;
        }

        // B → BRANCH xref
        if (is_b(word, imm)) {
            uint64_t target = pc + (uint64_t)imm;
            xrefs.push_back({pc, target, XrefType::BRANCH});
            continue;
        }

        // B.cond → BRANCH xref
        if (is_bcond(word, imm)) {
            uint64_t target = pc + (uint64_t)imm;
            xrefs.push_back({pc, target, XrefType::BRANCH});
            continue;
        }

        // CBZ/CBNZ → BRANCH xref
        if (is_cbz_cbnz(word, imm)) {
            uint64_t target = pc + (uint64_t)imm;
            xrefs.push_back({pc, target, XrefType::BRANCH});
            continue;
        }

        // TBZ/TBNZ → BRANCH xref
        if (is_tbz_tbnz(word, imm)) {
            uint64_t target = pc + (uint64_t)imm;
            xrefs.push_back({pc, target, XrefType::BRANCH});
            continue;
        }

        // ADRP — record for potential pairing
        uint8_t rd_adrp = 0;
        int64_t page_off = 0;
        if (is_adrp(word, page_off, rd_adrp)) {
            uint64_t page_pc = pc & ~(uint64_t)0xFFF;
            adrp_page[rd_adrp]  = (uint64_t)((int64_t)page_pc + page_off);
            adrp_valid[rd_adrp] = true;
            continue;
        }

        // ADD after ADRP → data xref
        uint8_t rn_add = 0, rd_add = 0;
        int64_t add_imm = 0;
        if (is_add_imm(word, rn_add, rd_add, add_imm) && adrp_valid[rn_add]) {
            uint64_t target = adrp_page[rn_add] + (uint64_t)add_imm;
            if (target < section_base || target >= section_end) {
                xrefs.push_back({pc, target, XrefType::DATA});
            }
            adrp_valid[rn_add] = false;
            continue;
        }

        // LDR after ADRP → data xref
        uint8_t rn_ldr = 0;
        if (is_ldr_imm(word, rn_ldr) && adrp_valid[rn_ldr]) {
            // imm from LDR
            int32_t ldr_imm = (int32_t)((word >> 10) & 0xFFF);
            int scale = ((word >> 30) & 3); // 0=8b,1=16b,2=32b,3=64b
            ldr_imm <<= scale;
            uint64_t target = adrp_page[rn_ldr] + (uint64_t)ldr_imm;
            if (target < section_base || target >= section_end) {
                xrefs.push_back({pc, target, XrefType::DATA});
            }
            adrp_valid[rn_ldr] = false;
            continue;
        }

        // Any other instruction resets ADRP tracking for written registers
        // (simple heuristic: reset all on non-paired instructions that write)
        // Only reset if the instruction isn't ADRP-related
    }

    LOGI("Detected %zu xrefs", xrefs.size());
    return xrefs;
}
