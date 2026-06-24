#pragma once

#include <cstdint>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Minimal ELF64 structures (ARM64 only, little-endian)
// ---------------------------------------------------------------------------

static constexpr uint32_t ELFMAG0   = 0x7f;
static constexpr uint32_t ELFMAG1   = 'E';
static constexpr uint32_t ELFMAG2   = 'L';
static constexpr uint32_t ELFMAG3   = 'F';
static constexpr uint8_t  ELFCLASS64 = 2;
static constexpr uint8_t  ELFDATA2LSB = 1;
static constexpr uint16_t ET_DYN    = 3;
static constexpr uint16_t EM_AARCH64 = 183;

static constexpr uint32_t SHT_NULL     = 0;
static constexpr uint32_t SHT_PROGBITS = 1;
static constexpr uint32_t SHT_SYMTAB   = 2;
static constexpr uint32_t SHT_STRTAB   = 3;
static constexpr uint32_t SHT_RELA     = 4;
static constexpr uint32_t SHT_DYNSYM   = 11;
static constexpr uint32_t SHT_REL      = 9;

static constexpr uint64_t SHF_EXECINSTR = 0x4;
static constexpr uint64_t SHF_ALLOC     = 0x2;

static constexpr uint8_t STB_LOCAL  = 0;
static constexpr uint8_t STB_GLOBAL = 1;
static constexpr uint8_t STB_WEAK   = 2;
static constexpr uint8_t STT_FUNC   = 2;
static constexpr uint8_t STT_OBJECT = 1;

// Special section indices
static constexpr uint16_t SHN_UNDEF    = 0;       // undefined / external
static constexpr uint16_t SHN_LORESERVE = 0xff00; // start of reserved range

#define ELF64_ST_BIND(info)  ((info) >> 4)
#define ELF64_ST_TYPE(info)  ((info) & 0x0f)

// RELA relocation (SHT_RELA sections such as .rela.plt, .rela.dyn)
#define ELF64_R_SYM(i)  ((uint32_t)((uint64_t)(i) >> 32))
#define ELF64_R_TYPE(i) ((uint32_t)((uint64_t)(i) & 0xffffffff))

#pragma pack(push, 1)
struct Elf64_Rela {
    uint64_t r_offset;   // VA of GOT/PLT slot
    uint64_t r_info;     // symbol index (upper 32) | reloc type (lower 32)
    int64_t  r_addend;
};

struct Elf64_Ehdr {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct Elf64_Shdr {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
};

struct Elf64_Sym {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
};

struct Elf64_Phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};
#pragma pack(pop)

// ---------------------------------------------------------------------------
// Parsed results
// ---------------------------------------------------------------------------

struct ParsedSymbol {
    uint64_t    address;
    uint64_t    size;
    std::string name;
    uint8_t     type;       // STT_FUNC / STT_OBJECT / etc.
    uint8_t     binding;    // STB_LOCAL / STB_GLOBAL / STB_WEAK
    bool        is_import;
};

struct ParsedSection {
    std::string name;
    uint32_t    type;
    uint64_t    flags;
    uint64_t    address;
    uint64_t    offset;
    uint64_t    size;
    bool        is_executable() const { return (flags & SHF_EXECINSTR) != 0; }
};

struct ParsedFunction {
    uint64_t    address;
    uint64_t    size;
    std::string name;
    int         kind = 1;   // 0=local(sub_), 1=named, 2=thunk(j_)
};

struct ElfParseResult {
    bool                        ok = false;
    std::string                 error;
    std::vector<uint8_t>        data;         // full file contents
    std::vector<ParsedSection>  sections;
    std::vector<ParsedSymbol>   symbols;
    std::vector<ParsedFunction> functions;
    uint64_t                    load_bias = 0;// VA offset for PIE
};

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

// Parse an ARM64 ELF64 .so file.
// Returns ElfParseResult; check .ok before use.
ElfParseResult elf_parse(const std::string& path);

// Compute SHA-256 of a file, returned as 64-char hex string.
std::string sha256_file(const std::string& path);
