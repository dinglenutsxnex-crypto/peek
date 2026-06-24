#include "elf_parser.h"

#include <android/log.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iomanip>

#define TAG "PeekELF"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ---------------------------------------------------------------------------
// SHA-256 (RFC 6234 – public domain roll)
// ---------------------------------------------------------------------------

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

struct Sha256Ctx {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
};

static uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_transform(Sha256Ctx& ctx, const uint8_t* block) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)block[i*4]   << 24) | ((uint32_t)block[i*4+1] << 16)
             | ((uint32_t)block[i*4+2] <<  8) |  (uint32_t)block[i*4+3];
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(w[i-15],7) ^ rotr32(w[i-15],18) ^ (w[i-15]>>3);
        uint32_t s1 = rotr32(w[i-2],17) ^ rotr32(w[i-2],19)  ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=ctx.state[0], b=ctx.state[1], c=ctx.state[2], d=ctx.state[3];
    uint32_t e=ctx.state[4], f=ctx.state[5], g=ctx.state[6], h=ctx.state[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1  = rotr32(e,6)  ^ rotr32(e,11) ^ rotr32(e,25);
        uint32_t ch  = (e & f) ^ (~e & g);
        uint32_t tmp1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0  = rotr32(a,2)  ^ rotr32(a,13) ^ rotr32(a,22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t tmp2 = S0 + maj;
        h=g; g=f; f=e; e=d+tmp1;
        d=c; c=b; b=a; a=tmp1+tmp2;
    }
    ctx.state[0]+=a; ctx.state[1]+=b; ctx.state[2]+=c; ctx.state[3]+=d;
    ctx.state[4]+=e; ctx.state[5]+=f; ctx.state[6]+=g; ctx.state[7]+=h;
}

static void sha256_init(Sha256Ctx& ctx) {
    ctx.state[0]=0x6a09e667; ctx.state[1]=0xbb67ae85;
    ctx.state[2]=0x3c6ef372; ctx.state[3]=0xa54ff53a;
    ctx.state[4]=0x510e527f; ctx.state[5]=0x9b05688c;
    ctx.state[6]=0x1f83d9ab; ctx.state[7]=0x5be0cd19;
    ctx.count = 0;
}

static void sha256_update(Sha256Ctx& ctx, const uint8_t* data, size_t len) {
    size_t partial = ctx.count & 63;
    ctx.count += len;
    if (partial + len >= 64) {
        size_t used = 64 - partial;
        memcpy(ctx.buf + partial, data, used);
        sha256_transform(ctx, ctx.buf);
        data += used; len -= used; partial = 0;
        while (len >= 64) {
            sha256_transform(ctx, data);
            data += 64; len -= 64;
        }
    }
    memcpy(ctx.buf + partial, data, len);
}

static void sha256_final(Sha256Ctx& ctx, uint8_t digest[32]) {
    uint64_t bit_count = ctx.count * 8;
    uint8_t one = 0x80;
    sha256_update(ctx, &one, 1);
    while ((ctx.count & 63) != 56) {
        uint8_t z = 0;
        sha256_update(ctx, &z, 1);
    }
    uint8_t len_be[8];
    for (int i = 7; i >= 0; --i) { len_be[i] = (uint8_t)(bit_count & 0xff); bit_count >>= 8; }
    sha256_update(ctx, len_be, 8);
    for (int i = 0; i < 8; ++i) {
        digest[i*4+0] = (ctx.state[i] >> 24) & 0xff;
        digest[i*4+1] = (ctx.state[i] >> 16) & 0xff;
        digest[i*4+2] = (ctx.state[i] >>  8) & 0xff;
        digest[i*4+3] =  ctx.state[i]         & 0xff;
    }
}

std::string sha256_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return "";
    Sha256Ctx ctx; sha256_init(ctx);
    uint8_t buf[65536];
    while (f) {
        f.read(reinterpret_cast<char*>(buf), sizeof(buf));
        auto n = f.gcount();
        if (n > 0) sha256_update(ctx, buf, (size_t)n);
    }
    uint8_t digest[32]; sha256_final(ctx, digest);
    std::ostringstream oss;
    for (int i = 0; i < 32; ++i) oss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    return oss.str();
}

// ---------------------------------------------------------------------------
// ELF parsing
// ---------------------------------------------------------------------------

static bool read_file(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return false;
    auto sz = f.tellg();
    if (sz <= 0) return false;
    f.seekg(0);
    out.resize((size_t)sz);
    f.read(reinterpret_cast<char*>(out.data()), sz);
    return f.good() || f.eof();
}

static const char* strtab_str(const std::vector<uint8_t>& data,
                               uint64_t strtab_offset, uint64_t strtab_size,
                               uint32_t name_idx) {
    if (strtab_offset == 0 || name_idx >= strtab_size) return "";
    if (strtab_offset + strtab_size > data.size()) return "";
    const char* base = reinterpret_cast<const char*>(data.data() + strtab_offset);
    // Ensure null-terminated within bounds
    size_t max = (size_t)(strtab_size - name_idx);
    const char* s = base + name_idx;
    size_t len = strnlen(s, max);
    if (len == 0) return "";
    return s;
}

// Returns true if a section name looks like a PLT/stub trampoline section.
static bool is_plt_section_name(const std::string& name) {
    return name == ".plt"     ||
           name == ".plt.got" ||
           name == ".plt.sec" ||
           name == ".iplt"    ||
           (name.size() >= 4 && name.substr(0, 4) == ".plt");
}

ElfParseResult elf_parse(const std::string& path) {
    ElfParseResult res;

    if (!read_file(path, res.data)) {
        res.error = "Failed to read file: " + path;
        return res;
    }

    const auto& d = res.data;
    if (d.size() < sizeof(Elf64_Ehdr)) {
        res.error = "File too small for ELF header";
        return res;
    }

    auto* ehdr = reinterpret_cast<const Elf64_Ehdr*>(d.data());

    // Magic
    if (ehdr->e_ident[0] != ELFMAG0 || ehdr->e_ident[1] != ELFMAG1 ||
        ehdr->e_ident[2] != ELFMAG2 || ehdr->e_ident[3] != ELFMAG3) {
        res.error = "Not an ELF file";
        return res;
    }
    if (ehdr->e_ident[4] != ELFCLASS64) {
        res.error = "Not ELF64";
        return res;
    }
    if (ehdr->e_ident[5] != ELFDATA2LSB) {
        res.error = "Not little-endian ELF";
        return res;
    }
    if (ehdr->e_machine != EM_AARCH64) {
        res.error = "Not AArch64 (ARM64)";
        return res;
    }

    // Section headers
    uint64_t shoff    = ehdr->e_shoff;
    uint16_t shnum    = ehdr->e_shnum;
    uint16_t shentsize = ehdr->e_shentsize;
    uint16_t shstrndx = ehdr->e_shstrndx;

    if (shoff == 0 || shnum == 0) {
        res.error = "No section headers";
        return res;
    }
    if (shoff + (uint64_t)shnum * shentsize > d.size()) {
        res.error = "Section header table out of bounds";
        return res;
    }

    auto get_shdr = [&](uint16_t idx) -> const Elf64_Shdr* {
        return reinterpret_cast<const Elf64_Shdr*>(d.data() + shoff + idx * shentsize);
    };

    // Section name string table
    uint64_t shstrtab_off = 0, shstrtab_size = 0;
    if (shstrndx != 0 && shstrndx < shnum) {
        auto* ss = get_shdr(shstrndx);
        shstrtab_off  = ss->sh_offset;
        shstrtab_size = ss->sh_size;
    }

    // Parse sections
    uint64_t strtab_off = 0, strtab_size = 0;
    uint64_t symtab_off = 0, symtab_size = 0;
    uint64_t dynstr_off = 0, dynstr_size = 0;
    uint64_t dynsym_off = 0, dynsym_size = 0;

    for (uint16_t i = 0; i < shnum; ++i) {
        auto* sh = get_shdr(i);
        if (sh->sh_offset + sh->sh_size > d.size()) continue;

        const char* sname = strtab_str(d, shstrtab_off, shstrtab_size, sh->sh_name);

        ParsedSection ps;
        ps.name    = sname ? sname : "";
        ps.type    = sh->sh_type;
        ps.flags   = sh->sh_flags;
        ps.address = sh->sh_addr;
        ps.offset  = sh->sh_offset;
        ps.size    = sh->sh_size;
        res.sections.push_back(ps);

        if (sh->sh_type == SHT_STRTAB && ps.name == ".strtab") {
            strtab_off  = sh->sh_offset;
            strtab_size = sh->sh_size;
        }
        if (sh->sh_type == SHT_SYMTAB) {
            symtab_off  = sh->sh_offset;
            symtab_size = sh->sh_size;
        }
        if (sh->sh_type == SHT_STRTAB && ps.name == ".dynstr") {
            dynstr_off  = sh->sh_offset;
            dynstr_size = sh->sh_size;
        }
        if (sh->sh_type == SHT_DYNSYM) {
            dynsym_off  = sh->sh_offset;
            dynsym_size = sh->sh_size;
        }
    }

    // Helper to parse symbol table.
    // is_dynsym=true  → parsing .dynsym; apply broadened import detection.
    // is_dynsym=false → parsing .symtab; only SHN_UNDEF signals import.
    auto parse_syms = [&](uint64_t sym_off, uint64_t sym_size,
                           uint64_t str_off, uint64_t str_size,
                           bool is_dynsym) {
        if (sym_off == 0 || sym_size < sizeof(Elf64_Sym)) return;
        size_t count = (size_t)(sym_size / sizeof(Elf64_Sym));

        for (size_t si = 0; si < count; ++si) {
            auto* sym = reinterpret_cast<const Elf64_Sym*>(d.data() + sym_off + si * sizeof(Elf64_Sym));

            // Always skip the null symbol at index 0 (all fields zero).
            // For non-dynsym tables, also skip any entry with both value and
            // size equal to zero — these carry no useful information.
            // For dynsym, SHN_UNDEF entries (shndx==0) often have value==0
            // and size==0 because they are externally resolved; keep them.
            bool is_undef = (sym->st_shndx == SHN_UNDEF);
            if (sym->st_name == 0 && sym->st_value == 0 && sym->st_size == 0 &&
                sym->st_info == 0 && sym->st_shndx == 0) {
                continue; // truly null entry
            }
            if (!is_undef && sym->st_value == 0 && sym->st_size == 0) {
                continue; // no address and no size — nothing useful
            }

            ParsedSymbol ps;
            ps.address = sym->st_value;
            ps.size    = sym->st_size;
            ps.type    = ELF64_ST_TYPE(sym->st_info);
            ps.binding = ELF64_ST_BIND(sym->st_info);

            // --- Broadened import detection ---
            // Signal 1: SHN_UNDEF — symbol has no local definition.
            bool import_by_undef = is_undef;

            // Signal 2: For .dynsym entries with a valid section index,
            // check whether the symbol's address falls inside a PLT section.
            // PLT stubs are trampolines to imported functions; they are
            // present in the binary but resolve externally at runtime.
            bool import_by_plt = false;
            if (is_dynsym && !is_undef &&
                sym->st_shndx < SHN_LORESERVE && sym->st_value != 0) {
                for (const auto& sec : res.sections) {
                    if (sec.address == 0 || sec.size == 0) continue;
                    if (sym->st_value >= sec.address &&
                        sym->st_value <  sec.address + sec.size) {
                        if (is_plt_section_name(sec.name)) {
                            import_by_plt = true;
                        }
                        break;
                    }
                }
            }

            ps.is_import = import_by_undef || import_by_plt;

            const char* name = strtab_str(d, str_off, str_size, sym->st_name);
            ps.name = name ? name : "";

            if (!ps.name.empty()) {
                res.symbols.push_back(ps);
            }

            // Functions with a known address that are NOT imports are candidates
            // for disassembly. Accept size==0 here (common for tail-call thunks /
            // "jumpout" stubs — compiler leaves st_size=0).  The analysis pipeline
            // will estimate the size from the next function boundary.
            if (ps.type == STT_FUNC && ps.address != 0 && !ps.is_import) {
                ParsedFunction pf;
                pf.address = ps.address;
                pf.size    = ps.size;   // may be 0; pipeline uses estimate_size()
                pf.name    = ps.name;
                res.functions.push_back(pf);
            }
        }
    };

    // Parse dynamic symbol table first (has broadened import detection),
    // then the full symbol table.
    parse_syms(dynsym_off, dynsym_size, dynstr_off, dynstr_size, true);
    parse_syms(symtab_off, symtab_size, strtab_off, strtab_size, false);

    // If no functions from symbols, fall back: every executable section is one big "function"
    if (res.functions.empty()) {
        for (auto& sec : res.sections) {
            if (sec.is_executable() && sec.size > 0) {
                ParsedFunction pf;
                pf.address = sec.address;
                pf.size    = sec.size;
                pf.name    = sec.name.empty() ? "<code>" : sec.name;
                res.functions.push_back(pf);
            }
        }
    }

    // Count how many imports were detected for logging
    size_t import_count = 0;
    for (const auto& sym : res.symbols) {
        if (sym.is_import) ++import_count;
    }

    LOGI("Parsed ELF: %zu sections, %zu symbols (%zu imports), %zu functions",
         res.sections.size(), res.symbols.size(), import_count, res.functions.size());

    res.ok = true;
    return res;
}
