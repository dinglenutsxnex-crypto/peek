#pragma once
#include "decompiler/loadimage.hh"
#include "elf_parser.h"

using namespace ghidra;

// Mirrors R2LoadImage: serves full ELF virtual address space to the
// Ghidra decompiler.  loadFill maps VA requests to ELF section data;
// unmapped addresses return zero bytes so followFlow never hard-faults.
class PeekLoadImage : public LoadImage {
    const ElfParseResult& elf_;
    // Optional override bytes for the target function (tail-call rewrite).
    const uint8_t* patch_bytes_ = nullptr;
    uint64_t       patch_addr_  = 0;
    size_t         patch_len_   = 0;

public:
    explicit PeekLoadImage(const ElfParseResult& elf)
        : LoadImage("peek_elf"), elf_(elf) {}

    void setPatch(const uint8_t* bytes, uint64_t addr, size_t len) {
        patch_bytes_ = bytes;
        patch_addr_  = addr;
        patch_len_   = len;
    }

    void loadFill(uint1* ptr, int4 size, const Address& addr) override;
    std::string getArchType() const override { return "peek_elf"; }
    void adjustVma(long) override {}  // ELF sections already carry correct VAs
};
