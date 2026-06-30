#pragma once
#include "decompiler/sleigh_arch.hh"
#include "elf_parser.h"

using namespace ghidra;

class PeekScope;

// Mirrors R2Architecture: a SleighArchitecture subclass that overrides
// buildLoader (full ELF byte map), buildDatabase (PeekScope), and
// buildCoreTypes (stdint names instead of Ghidra's byte/word/dword).
class PeekArchitecture : public SleighArchitecture {
    const ElfParseResult& elf_;
    PeekScope*            peek_scope_   = nullptr;
    const uint8_t*        patch_bytes_  = nullptr;
    uint64_t              patch_addr_   = 0;
    size_t                patch_len_    = 0;

protected:
    void buildLoader(DocumentStorage& store) override;
    Scope* buildDatabase(DocumentStorage& store) override;
    void buildCoreTypes(DocumentStorage& store) override;

public:
    PeekArchitecture(const ElfParseResult& elf, std::ostream* errs);

    PeekScope* getPeekScope() const { return peek_scope_; }

    // Set before init() — picked up by buildLoader() to overlay patched bytes.
    void setPatch(const uint8_t* bytes, uint64_t addr, size_t len) {
        patch_bytes_ = bytes; patch_addr_ = addr; patch_len_ = len;
    }
};
