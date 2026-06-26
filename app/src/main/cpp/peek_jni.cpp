/**
 * peek_jni.cpp — JNI bridge + full analysis pipeline.
 *
 * JNI contract (mirrored in PeekNative.kt):
 *   nativeOpenBinary(path, dbDir)               → Long handle
 *   nativeCloseBinary(handle)
 *   nativeGetLastError(handle)                  → String
 *   nativeGetFunctionList(handle)               → LongArray [id,addr,size, …]
 *   nativeGetFunctionNames(handle)              → Array<String>
 *   nativeGetInstructions(h,fid,limit,off)      → LongArray [addr,size, …]
 *   nativeGetInstructionStrings(h,fid,lim,off)  → Array<String> [bytes,mnem,ops, …]
 *   nativeGetInstructionCount(handle,funcId)    → Long
 *   nativeGetXrefs(handle,address)              → LongArray [from,to, …]
 *   nativeGetXrefTypes(handle,address)          → Array<String>
 *   nativeGetSymbols(handle)                    → LongArray [addr,isImport, …]
 *   nativeGetSymbolStrings(handle)              → Array<String> [name,typeStr, …]
 *   nativeInitDecompiler(specDir)               → Boolean
 *   nativeDecompileFunction(handle, funcId)     → String
 */

#include "elf_parser.h"
#include "disassembler.h"
#include "xref_detector.h"
#include "db_cache.h"
#include "decompiler_bridge.h"
#include "jni_annotator.h"

#include <jni.h>
#include <android/log.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#define TAG "PeekJNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ---------------------------------------------------------------------------
// Analysis context
// ---------------------------------------------------------------------------

struct AnalysisContext {
    std::string              file_path;
    std::string              file_hash;
    std::string              tmp_dir;   // writable dir for decompiler temp files
    int64_t                  binary_id = -1;
    std::string              last_error;
    std::unique_ptr<AnalysisDb> db;
};

static std::string jstr(JNIEnv* env, jstring s) {
    if (!s) return "";
    const char* c = env->GetStringUTFChars(s, nullptr);
    std::string r = c;
    env->ReleaseStringUTFChars(s, c);
    return r;
}

// ---------------------------------------------------------------------------
// Analysis helpers
// ---------------------------------------------------------------------------

// Returns pointer into elf.data for a given VA range, or nullptr.
// Only walks executable sections (for code bytes).
static const uint8_t* va_to_ptr(const ElfParseResult& elf,
                                  uint64_t va, uint64_t size) {
    for (const auto& sec : elf.sections) {
        if (!sec.is_executable()) continue;
        if (va >= sec.address && va < sec.address + sec.size) {
            uint64_t off = va - sec.address;
            if (off + size <= sec.size &&
                sec.offset + off + size <= elf.data.size()) {
                return elf.data.data() + sec.offset + off;
            }
        }
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// ELF string + data-reference resolution helpers
// ---------------------------------------------------------------------------

// Read an 8-byte little-endian value from a virtual address in the ELF.
// Returns 0 and sets ok=false if the VA is not mapped or OOB.
static uint64_t elf_read_u64le(const ElfParseResult& elf, uint64_t va, bool& ok) {
    for (const auto& sec : elf.sections) {
        if (sec.size < 8) continue;
        if (va < sec.address || va + 8 > sec.address + sec.size) continue;
        uint64_t file_off = sec.offset + (va - sec.address);
        if (file_off + 8 > elf.data.size()) continue;
        const uint8_t* b = elf.data.data() + file_off;
        ok = true;
        return  (uint64_t)b[0]        | ((uint64_t)b[1] << 8)  |
                ((uint64_t)b[2] << 16) | ((uint64_t)b[3] << 24) |
                ((uint64_t)b[4] << 32) | ((uint64_t)b[5] << 40) |
                ((uint64_t)b[6] << 48) | ((uint64_t)b[7] << 56);
    }
    ok = false;
    return 0;
}

// Read a null-terminated printable ASCII string from ANY mapped ELF section.
//
// Many Ghidra xRam<addr> tokens point into a pointer table (.data/.rodata)
// rather than directly to a string — the 8 bytes at that address are a
// pointer to the actual string.  We therefore try:
//   1. Direct: read string bytes at va.
//   2. Deref:  read 8-byte LE pointer at va, then read string there.
// The longer / more valid result wins.  Returns "" if nothing is found.
static std::string elf_read_cstring(const ElfParseResult& elf,
                                     uint64_t va,
                                     size_t max_len = 512) {
    auto try_at = [&](uint64_t addr) -> std::string {
        for (const auto& sec : elf.sections) {
            if (sec.size == 0) continue;
            if (addr < sec.address || addr >= sec.address + sec.size) continue;
            uint64_t file_off = sec.offset + (addr - sec.address);
            if (file_off >= elf.data.size()) continue;
            std::string s;
            for (size_t i = 0; i < max_len; ++i) {
                if (file_off + i >= elf.data.size()) break;
                uint8_t b = elf.data[file_off + i];
                if (b == 0) return s;
                // Allow printable ASCII + common escapes (\t \n)
                if (b == '\t' || b == '\n') { s += b; continue; }
                if (b < 0x20 || b > 0x7e) return "";
                s += static_cast<char>(b);
            }
            return "";
        }
        return "";
    };

    std::string direct = try_at(va);

    // Heuristic: if direct is short (<4 chars) it may be pointer bytes mis-read as text.
    // Try dereferencing.
    bool ok = false;
    uint64_t ptr = elf_read_u64le(elf, va, ok);
    std::string deref;
    if (ok && ptr != 0 && ptr != va)
        deref = try_at(ptr);

    // Prefer the longer, more printable result.
    return (deref.size() > direct.size()) ? deref : direct;
}

// Try to match `target` VA against named entries in functions + symbols.
// Returns the name or "" if nothing useful found.
static std::string lookup_va_name(const ElfParseResult& elf, uint64_t target) {
    if (target == 0) return "";
    for (const auto& fn : elf.functions) {
        if (fn.address != target || fn.name.empty()) continue;
        if (fn.name.size() > 4 && fn.name[3]=='_' &&
            (fn.name[0]=='s'||fn.name[0]=='j')) continue;
        return fn.name;
    }
    for (const auto& sym : elf.symbols) {
        if (sym.address != target || sym.name.empty()) continue;
        if (sym.name.size() > 4 && sym.name[3]=='_' &&
            (sym.name[0]=='s'||sym.name[0]=='j')) continue;
        return sym.name;
    }
    return "";
}

static std::string elf_resolve_funcptr(const ElfParseResult& elf, uint64_t va) {
    // Path 1: read the 8-byte pointer stored at `va` and look up the target.
    // Works when the slot already contains the function VA (non-PIE or
    // pre-linked static data).
    bool ok = false;
    uint64_t target = elf_read_u64le(elf, va, ok);
    if (ok && target != 0) {
        std::string name = lookup_va_name(elf, target);
        if (!name.empty()) return name;
    }

    // Path 2: RELA fallback.
    // On Android ARM64, JNINativeMethod fnPtr fields are often filled by an
    // R_AARCH64_RELATIVE relocation (type 0x403).  The ELF file bytes at `va`
    // are 0 (or the raw addend) at this point; the real function VA lives in
    // the RELA entry's r_addend field.  Scan every SHT_RELA section for an
    // entry whose r_offset matches `va`.
    static constexpr uint32_t R_AARCH64_RELATIVE = 0x403;
    for (const auto& sec : elf.sections) {
        if (sec.type != SHT_RELA) continue;
        const size_t entry_size = sizeof(Elf64_Rela);
        if (sec.size < entry_size) continue;
        uint64_t n = sec.size / entry_size;
        for (uint64_t i = 0; i < n; ++i) {
            uint64_t off = sec.offset + i * entry_size;
            if (off + entry_size > elf.data.size()) break;
            const Elf64_Rela* r =
                reinterpret_cast<const Elf64_Rela*>(elf.data.data() + off);
            if (r->r_offset != va) continue;
            if (ELF64_R_TYPE(r->r_info) != R_AARCH64_RELATIVE) continue;
            std::string name = lookup_va_name(
                elf, static_cast<uint64_t>(r->r_addend));
            if (!name.empty()) return name;
        }
    }
    return "";
}

// Escape a C string literal for embedding in quotes in pseudocode.
// Handles backslash and double-quote; strips embedded newlines/tabs.
static std::string escape_for_literal(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 4);
    for (unsigned char c : s) {
        if (c == '"')  { out += "\\\""; }
        else if (c == '\\') { out += "\\\\"; }
        else if (c == '\n') { out += "\\n"; }
        else if (c == '\t') { out += "\\t"; }
        else out += static_cast<char>(c);
    }
    return out;
}

// JNI functions whose N-th argument (0-based, after env) is a C-string VA
// that Ghidra emits as a hex literal.  arg_after_env=0 means first real arg.
struct StringArgSpec { const char* func; int arg_after_env; };
static const StringArgSpec kStringArgFuncs[] = {
    {"FindClass",         0},
    {"DefineClass",       0},
    {"ThrowNew",          1},
    {"GetMethodID",       1},  // name
    {"GetMethodID",       2},  // sig
    {"GetStaticMethodID", 1},
    {"GetStaticMethodID", 2},
    {"GetFieldID",        1},
    {"GetFieldID",        2},
    {"GetStaticFieldID",  1},
    {"GetStaticFieldID",  2},
    {"NewStringUTF",      0},
};

// Resolve Ghidra data references and JNI string arguments INLINE.
//
// Pass 1 — xRam<hex16>: replaces the entire token with "string" if the
//   address resolves to printable ASCII.  If not resolvable, keeps the
//   original token unchanged so the user can still see the address.
//
// Pass 2 — JNI string args: after vtable resolution, patterns like
//   ->FindClass(env, 0x470e) are found; if the hex resolves to a string
//   the literal 0x... is replaced with "string" inline.
static std::string resolve_data_refs(const std::string& code,
                                      const ElfParseResult& elf) {
    // ---- Pass 1: xRam<16-digit-hex> → "string" --------------------------
    std::string out;
    out.reserve(code.size());
    {
        const char   XPFX[]    = "xRam";
        const size_t XPFX_LEN  = 4;
        size_t pos = 0;
        while (pos < code.size()) {
            size_t f = code.find(XPFX, pos);
            if (f == std::string::npos) { out.append(code, pos, std::string::npos); break; }
            // Word boundary before "xRam"
            if (f > 0 && (std::isalnum((unsigned char)code[f-1]) || code[f-1]=='_')) {
                out.append(code, pos, f - pos + 1);
                pos = f + 1;
                continue;
            }
            size_t p = f + XPFX_LEN;
            size_t hex_start = p;
            while (p < code.size() && std::isxdigit((unsigned char)code[p])) ++p;
            if (p - hex_start != 16) {
                out.append(code, pos, f - pos + 1);
                pos = f + 1;
                continue;
            }
            uint64_t va = std::strtoull(
                std::string(code, hex_start, 16).c_str(), nullptr, 16);
            std::string s = elf_read_cstring(elf, va);
            if (!s.empty()) {
                // Address holds (or points to) a C string — emit "string".
                out.append(code, pos, f - pos);
                out += '"';
                out += escape_for_literal(s);
                out += '"';
            } else {
                // Address may hold a function pointer — try to resolve it to
                // a symbol name (e.g. the fnPtr field of JNINativeMethod).
                std::string fn = elf_resolve_funcptr(elf, va);
                if (!fn.empty()) {
                    out.append(code, pos, f - pos);
                    out += fn;
                } else {
                    out.append(code, pos, p - pos); // keep xRam token as-is
                }
            }
            pos = p;
        }
    }

    // ---- Pass 2: JNI string args 0x<hex> → "string" ---------------------
    std::string out2;
    out2.reserve(out.size());
    {
        size_t pos = 0;
        while (pos < out.size()) {
            size_t arrow = out.find("->", pos);
            if (arrow == std::string::npos) {
                out2.append(out, pos, std::string::npos);
                break;
            }

            size_t fn_start = arrow + 2;
            size_t fn_end   = fn_start;
            while (fn_end < out.size() &&
                   (std::isalnum((unsigned char)out[fn_end]) || out[fn_end]=='_'))
                ++fn_end;
            std::string callee(out, fn_start, fn_end - fn_start);

            int resolve_args[4]; int resolve_n = 0;
            for (const auto& sas : kStringArgFuncs)
                if (callee == sas.func && resolve_n < 4)
                    resolve_args[resolve_n++] = sas.arg_after_env;

            if (resolve_n == 0 || fn_end >= out.size() || out[fn_end] != '(') {
                out2.append(out, pos, arrow - pos + 2);
                pos = arrow + 2;
                continue;
            }

            out2.append(out, pos, fn_end - pos + 1); // up to '('
            int  arg_idx     = 0;
            int  paren_depth = 1;
            size_t p = fn_end + 1;

            while (p < out.size() && paren_depth > 0) {
                char c = out[p];
                if (c == '(') { ++paren_depth; out2 += c; ++p; continue; }
                if (c == ')') { --paren_depth; out2 += c; ++p; continue; }
                if (c == ',' && paren_depth == 1) { ++arg_idx; out2 += c; ++p; continue; }

                bool should_resolve = false;
                for (int i = 0; i < resolve_n; ++i)
                    if (arg_idx == resolve_args[i] + 1)
                        should_resolve = true;

                if (should_resolve && p + 1 < out.size() &&
                    out[p] == '0' && (out[p+1] == 'x' || out[p+1] == 'X')) {
                    size_t hex_start = p + 2;
                    size_t q = hex_start;
                    while (q < out.size() && std::isxdigit((unsigned char)out[q])) ++q;
                    uint64_t va = std::strtoull(
                        std::string(out, hex_start, q - hex_start).c_str(), nullptr, 16);
                    std::string s = elf_read_cstring(elf, va);
                    if (!s.empty()) {
                        // Inline replace: drop 0x..., emit "string"
                        out2 += '"';
                        out2 += escape_for_literal(s);
                        out2 += '"';
                    } else {
                        out2.append(out, p, q - p); // keep original hex
                    }
                    p = q;
                } else {
                    out2 += c; ++p;
                }
            }
            pos = p;
        }
    }

    return out2;
}

// Aggregate VA bounds of all executable sections.
static void exec_bounds(const ElfParseResult& elf,
                         uint64_t& base, uint64_t& end) {
    base = UINT64_MAX; end = 0;
    for (const auto& sec : elf.sections) {
        if (!sec.is_executable() || sec.size == 0) continue;
        if (sec.address < base) base = sec.address;
        if (sec.address + sec.size > end) end = sec.address + sec.size;
    }
    if (base == UINT64_MAX) base = 0;
}

// Scan executable sections for ARM64 function prologues:
//   sub sp, sp, #N   followed immediately by   stp x29, x30, [sp, #M{!}]
// Any match that is not already in func_map gets added with an empty name
// (will be auto-named sub_ADDRESS later).
static void prologue_scan(const ElfParseResult& elf,
                           std::map<uint64_t, std::string>& func_map) {
    for (const auto& sec : elf.sections) {
        if (!sec.is_executable() || sec.size < 8) continue;
        const uint8_t* base = elf.data.data() + sec.offset;
        for (uint64_t off = 0; off + 8 <= sec.size; off += 4) {
            uint32_t w0, w1;
            std::memcpy(&w0, base + off,     4);
            std::memcpy(&w1, base + off + 4, 4);

            // sub sp, sp, #imm (64-bit): sf=1 op=1 S=0 100010 0 Rn=31 Rd=31
            // Mask checks that Rd and Rn are both sp (reg 31).
            bool is_sub_sp = (w0 & 0xFF8003FF) == 0xD10003FF;

            // stp x29, x30, [sp, #N] — signed-offset or pre-index variants.
            // Fixed register fields: Rt1=x29(29), Rn=sp(31), Rt2=x30(30) → 0x7BFD.
            bool is_stp_fp_lr =
                ((w1 & 0xFFC07FFF) == 0xA9007BFD) ||   // signed offset
                ((w1 & 0xFFC07FFF) == 0xA9807BFD);     // pre-index

            if (is_sub_sp && is_stp_fp_lr) {
                uint64_t va = sec.address + off;
                func_map.emplace(va, "");
            }
        }
    }
}

// Estimate function size from sorted func_map (distance to next start, capped).
static uint64_t estimate_size(uint64_t addr,
                               const std::map<uint64_t, std::string>& fm,
                               uint64_t code_end) {
    auto it = fm.upper_bound(addr);
    uint64_t next = (it != fm.end()) ? it->first : code_end;
    uint64_t sz   = (next > addr) ? (next - addr) : 0;
    return std::min(sz, (uint64_t)65536u);
}

// Generate IDA-style name: sub_ADDRESS (uppercase hex, no leading zeros).
static std::string sub_name(uint64_t addr) {
    std::ostringstream oss;
    oss << "sub_" << std::hex << std::uppercase << addr;
    return oss.str();
}

struct FuncEntry {
    uint64_t    addr;
    uint64_t    size;
    std::string name;
};

// Build a vector of sized FuncEntry from func_map, resolving symbol sizes
// where known and falling back to estimate_size otherwise.
static std::vector<FuncEntry> build_entries(
    const std::map<uint64_t, std::string>& fm,
    const ElfParseResult& elf,
    uint64_t code_base, uint64_t code_end)
{
    std::vector<FuncEntry> out;
    out.reserve(fm.size());
    for (const auto& [addr, name] : fm) {
        if (addr == 0 || addr < code_base || addr >= code_end) continue;

        uint64_t sz = 0;
        for (const auto& fn : elf.functions) {
            if (fn.address == addr && fn.size > 0) { sz = fn.size; break; }
        }
        if (sz == 0) sz = estimate_size(addr, fm, code_end);
        if (sz == 0) continue;

        out.push_back({addr, sz, name.empty() ? sub_name(addr) : name});
    }
    return out;
}

// ---------------------------------------------------------------------------
// Full analysis pipeline
// ---------------------------------------------------------------------------

static bool run_analysis(AnalysisContext& ctx) {
    LOGI("Starting analysis: %s", ctx.file_path.c_str());

    // --- ELF parse ---
    ElfParseResult elf = elf_parse(ctx.file_path);
    if (!elf.ok) {
        ctx.last_error = "ELF parse: " + elf.error;
        LOGE("%s", ctx.last_error.c_str());
        return false;
    }

    ctx.binary_id = ctx.db->insert_binary(ctx.file_hash, ctx.file_path);
    if (ctx.binary_id < 0) {
        ctx.last_error = "DB insert_binary: " + ctx.db->last_error();
        return false;
    }

    ctx.db->store_symbols(ctx.binary_id, elf.symbols);

    uint64_t code_base, code_end;
    exec_bounds(elf, code_base, code_end);

    // --- Phase 1: seed from symbol table ---
    // Accept size-0 entries (tail-call thunks / "jumpout" stubs that the linker
    // left with st_size==0).  build_entries() will call estimate_size() for them.
    std::map<uint64_t, std::string> func_map;
    for (const auto& fn : elf.functions) {
        if (fn.address != 0)
            func_map[fn.address] = fn.name;
    }

    // --- Phase 2: prologue scan ---
    prologue_scan(elf, func_map);

    // --- Phase 3: first disassembly pass on Phase 1+2 functions ---
    //   - cache DisasmResults (avoid re-disassembling in Phase 5)
    //   - collect all branch targets
    std::map<uint64_t, std::vector<DisasmInstruction>> disasm_cache;
    std::set<uint64_t>  branch_targets;
    std::vector<Xref>   all_xrefs;

    auto phase12 = build_entries(func_map, elf, code_base, code_end);

    for (const auto& fe : phase12) {
        const uint8_t* data = va_to_ptr(elf, fe.addr, fe.size);
        if (!data) continue;
        DisasmResult dr = disassemble_arm64(data, (size_t)fe.size, fe.addr);
        if (!dr.ok || dr.instructions.empty()) continue;

        disasm_cache[fe.addr] = dr.instructions;

        auto xrefs = detect_xrefs(dr.instructions, code_base, code_end);
        for (const auto& x : xrefs) {
            all_xrefs.push_back(x);
            if ((x.ref_type == XrefType::CALL || x.ref_type == XrefType::BRANCH) &&
                x.to_address >= code_base && x.to_address < code_end)
                branch_targets.insert(x.to_address);
        }
    }

    // --- Phase 3.5: thunk / "jumpout" labeling ---
    //
    // Build a GOT-VA → symbol-name map from .rela.plt (and .rela.dyn) so we
    // can resolve ADRP+LDR+BR PLT stubs to their import names.
    std::map<uint64_t, std::string> got_to_sym;
    {
        uint64_t dynsym_off = 0;
        uint64_t dynstr_off = 0;
        for (const auto& sec : elf.sections) {
            if (sec.name == ".dynsym") dynsym_off = sec.offset;
            if (sec.name == ".dynstr") dynstr_off  = sec.offset;
        }

        auto resolve_rela = [&](uint64_t rela_off, uint64_t rela_size) {
            if (!rela_off || rela_size < sizeof(Elf64_Rela) ||
                !dynsym_off || !dynstr_off) return;
            size_t count = (size_t)(rela_size / sizeof(Elf64_Rela));
            for (size_t i = 0; i < count; ++i) {
                if (rela_off + (i + 1) * sizeof(Elf64_Rela) > elf.data.size()) break;
                const Elf64_Rela* rela = reinterpret_cast<const Elf64_Rela*>(
                    elf.data.data() + rela_off + i * sizeof(Elf64_Rela));
                uint32_t sym_idx = ELF64_R_SYM(rela->r_info);
                if (sym_idx == 0) continue;
                uint64_t sym_off = dynsym_off + (uint64_t)sym_idx * sizeof(Elf64_Sym);
                if (sym_off + sizeof(Elf64_Sym) > elf.data.size()) continue;
                const Elf64_Sym* sym = reinterpret_cast<const Elf64_Sym*>(
                    elf.data.data() + sym_off);
                uint64_t name_off = dynstr_off + sym->st_name;
                if (name_off >= elf.data.size()) continue;
                const char* cname = reinterpret_cast<const char*>(
                    elf.data.data() + name_off);
                size_t max_len = elf.data.size() - (size_t)name_off;
                std::string sname(cname, strnlen(cname, max_len));
                if (!sname.empty())
                    got_to_sym[rela->r_offset] = sname;
            }
        };

        for (const auto& sec : elf.sections) {
            if (sec.type == SHT_RELA && sec.size > 0 &&
                sec.offset + sec.size <= elf.data.size()) {
                resolve_rela(sec.offset, sec.size);
            }
        }
    }

    // Helper: parse a hex immediate from a Capstone operand token.
    // Accepts both "#0xABCD" and "0xABCD" forms.
    auto parse_hex_imm = [](const char* s, uint64_t& out) -> bool {
        if (*s == '#') ++s;
        if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
            char* ep;
            uint64_t v = (uint64_t)strtoull(s + 2, &ep, 16);
            if (ep != s + 2) { out = v; return true; }
        }
        return false;
    };

    for (auto& [addr, name] : func_map) {
        auto it = disasm_cache.find(addr);
        if (it == disasm_cache.end()) continue;
        const auto& insns = it->second;
        if (insns.empty() || insns.size() > 5) continue;   // thunks are tiny

        const auto& last = insns.back();

        // ── Case A: direct unconditional branch "b #target" ──────────────────
        if (last.mnemonic == "b") {
            uint64_t target = 0;
            if (!parse_hex_imm(last.operands.c_str(), target) || target == addr)
                continue;
            auto tgt_it = func_map.find(target);
            std::string base = (tgt_it != func_map.end() && !tgt_it->second.empty())
                               ? tgt_it->second : sub_name(target);
            name = (base.size() >= 2 && base.substr(0, 2) == "j_") ? base : "j_" + base;
            LOGI("Direct thunk 0x%llx → %s", (unsigned long long)addr, name.c_str());
            continue;
        }

        // ── Case B: indirect branch "br Xn" — resolve via GOT ────────────────
        // Pattern: ADRP Xd, #page + LDR Xt, [Xd, #off] + (optional ADD) + BR Xt
        // Capstone emits the ADRP page as an absolute VA; the LDR offset is a
        // byte offset.  GOT_VA = adrp_page + ldr_byte_offset.
        if (last.mnemonic == "br") {
            uint64_t adrp_page = 0, ldr_off = 0;
            bool found_adrp = false, found_ldr = false;

            for (size_t k = 0; k < insns.size() - 1; ++k) {
                if (!found_adrp && insns[k].mnemonic == "adrp") {
                    // op_str: "x16, #0x17000"  — take the part after ", #"
                    auto& ops = insns[k].operands;
                    auto hash = ops.find('#');
                    if (hash != std::string::npos &&
                        parse_hex_imm(ops.c_str() + hash, adrp_page))
                        found_adrp = true;
                }
                if (found_adrp && !found_ldr && insns[k].mnemonic == "ldr") {
                    // op_str: "x17, [x16, #0xfd8]"  — offset after the last '#'
                    auto& ops = insns[k].operands;
                    auto hash = ops.rfind('#');
                    if (hash != std::string::npos &&
                        parse_hex_imm(ops.c_str() + hash, ldr_off))
                        found_ldr = true;
                }
            }

            if (!found_adrp || !found_ldr) continue;

            uint64_t got_va = adrp_page + ldr_off;
            auto got_it = got_to_sym.find(got_va);
            if (got_it == got_to_sym.end()) continue;

            name = "j_" + got_it->second;
            LOGI("PLT thunk 0x%llx → %s (GOT 0x%llx)",
                 (unsigned long long)addr, name.c_str(), (unsigned long long)got_va);
        }
    }

    // --- Phase 4: branch-target discovery ---
    //   Add a target as a new sub_ADDRESS function only if:
    //   (a) not already in func_map, AND
    //   (b) not inside the body of any already-known function.
    for (uint64_t t : branch_targets) {
        if (func_map.count(t)) continue;
        bool inside = false;
        for (const auto& fe : phase12) {
            if (t > fe.addr && t < fe.addr + fe.size) { inside = true; break; }
        }
        if (!inside) func_map[t] = "";
    }

    // --- Phase 5: build final function list and store everything ---
    auto all_entries = build_entries(func_map, elf, code_base, code_end);
    LOGI("Functions: %zu (symbol/prologue: %zu, branch-target: %zu)",
         all_entries.size(), phase12.size(),
         all_entries.size() > phase12.size() ? all_entries.size() - phase12.size() : 0u);

    {
        std::vector<ParsedFunction> to_store;
        to_store.reserve(all_entries.size());
        for (const auto& fe : all_entries) {
            // Classify by name prefix: j_=thunk(2), sub_/empty=local(0), else=named(1)
            int kind = 1;
            const auto& n = fe.name;
            if (n.size() >= 2 && n[0] == 'j' && n[1] == '_') {
                kind = 2;
            } else if (n.empty() ||
                       (n.size() >= 4 && n[0]=='s' && n[1]=='u' && n[2]=='b' && n[3]=='_')) {
                kind = 0;
            }
            to_store.push_back({fe.addr, fe.size, fe.name, kind});
        }
        ctx.db->store_functions(ctx.binary_id, to_store);
    }

    // Disassemble & store instructions; collect xrefs for newly discovered fns.
    for (const auto& fe : all_entries) {
        std::vector<DisasmInstruction> insns;

        auto cached = disasm_cache.find(fe.addr);
        if (cached != disasm_cache.end()) {
            insns = cached->second;
        } else {
            const uint8_t* data = va_to_ptr(elf, fe.addr, fe.size);
            if (!data) continue;
            DisasmResult dr = disassemble_arm64(data, (size_t)fe.size, fe.addr);
            if (!dr.ok || dr.instructions.empty()) continue;

            auto xrefs = detect_xrefs(dr.instructions, code_base, code_end);
            all_xrefs.insert(all_xrefs.end(), xrefs.begin(), xrefs.end());

            insns = std::move(dr.instructions);
        }

        int64_t func_id = ctx.db->get_function_id(ctx.binary_id, fe.addr);
        if (func_id < 0) continue;
        for (auto& insn : insns) insn.function_id = (uint32_t)func_id;
        ctx.db->store_instructions(insns);
    }

    ctx.db->store_xrefs(ctx.binary_id, all_xrefs);

    LOGI("Analysis complete: binary_id=%lld, functions=%zu, xrefs=%zu",
         (long long)ctx.binary_id, all_entries.size(), all_xrefs.size());
    return true;
}

// ---------------------------------------------------------------------------
// JNI implementations (unchanged interface)
// ---------------------------------------------------------------------------

extern "C" {

JNIEXPORT jlong JNICALL
Java_com_nex_peek_PeekNative_nativeOpenBinary(JNIEnv* env, jobject,
                                               jstring jpath, jstring jdb_dir) {
    auto* ctx = new AnalysisContext();
    ctx->file_path = jstr(env, jpath);
    ctx->file_hash = sha256_file(ctx->file_path);
    if (ctx->file_hash.empty()) {
        ctx->last_error = "Could not hash file: " + ctx->file_path;
        return reinterpret_cast<jlong>(ctx);
    }
    std::string db_dir  = jstr(env, jdb_dir);
    ctx->tmp_dir        = db_dir;
    std::string db_path = db_dir + "/peek_cache.db";
    ctx->db = std::make_unique<AnalysisDb>(db_path);
    if (!ctx->db->open()) {
        ctx->last_error = "Cannot open DB: " + ctx->db->last_error();
        return reinterpret_cast<jlong>(ctx);
    }
    int64_t cached = ctx->db->find_binary(ctx->file_hash);
    if (cached >= 0) {
        ctx->binary_id = cached;
        LOGI("Cache hit binary_id=%lld", (long long)cached);
    } else {
        if (!run_analysis(*ctx))
            LOGE("Analysis failed: %s", ctx->last_error.c_str());
    }
    return reinterpret_cast<jlong>(ctx);
}

JNIEXPORT void JNICALL
Java_com_nex_peek_PeekNative_nativeCloseBinary(JNIEnv*, jobject, jlong h) {
    delete reinterpret_cast<AnalysisContext*>(h);
}

JNIEXPORT jstring JNICALL
Java_com_nex_peek_PeekNative_nativeGetLastError(JNIEnv* env, jobject, jlong h) {
    if (!h) return env->NewStringUTF("null handle");
    return env->NewStringUTF(reinterpret_cast<AnalysisContext*>(h)->last_error.c_str());
}

// Declared in crash_handler.cpp — async-signal-safe native crash handler.
extern "C" void peek_install_native_crash_handler(const char* crash_file_path);

JNIEXPORT void JNICALL
Java_com_nex_peek_PeekNative_nativeInstallCrashHandler(JNIEnv* env, jobject, jstring crashFilePath) {
    const char* path = env->GetStringUTFChars(crashFilePath, nullptr);
    peek_install_native_crash_handler(path);
    env->ReleaseStringUTFChars(crashFilePath, path);
}

JNIEXPORT jlongArray JNICALL
Java_com_nex_peek_PeekNative_nativeGetFunctionList(JNIEnv* env, jobject, jlong h) {
    if (!h) return env->NewLongArray(0);
    auto* ctx = reinterpret_cast<AnalysisContext*>(h);
    if (ctx->binary_id < 0) return env->NewLongArray(0);
    auto fns = ctx->db->get_functions(ctx->binary_id);
    jsize n = (jsize)(fns.size() * 4);
    jlongArray arr = env->NewLongArray(n);
    if (!n) return arr;
    std::vector<jlong> buf(n);
    for (size_t i = 0; i < fns.size(); ++i) {
        buf[i*4+0] = (jlong)fns[i].id;
        buf[i*4+1] = (jlong)fns[i].address;
        buf[i*4+2] = (jlong)fns[i].size;
        buf[i*4+3] = (jlong)fns[i].kind;
    }
    env->SetLongArrayRegion(arr, 0, n, buf.data());
    return arr;
}

JNIEXPORT jobjectArray JNICALL
Java_com_nex_peek_PeekNative_nativeGetFunctionNames(JNIEnv* env, jobject, jlong h) {
    jclass sc = env->FindClass("java/lang/String");
    if (!h) return env->NewObjectArray(0, sc, nullptr);
    auto* ctx = reinterpret_cast<AnalysisContext*>(h);
    if (ctx->binary_id < 0) return env->NewObjectArray(0, sc, nullptr);
    auto fns = ctx->db->get_functions(ctx->binary_id);
    jobjectArray arr = env->NewObjectArray((jsize)fns.size(), sc, nullptr);
    for (size_t i = 0; i < fns.size(); ++i) {
        jstring s = env->NewStringUTF(fns[i].name.c_str());
        env->SetObjectArrayElement(arr, (jsize)i, s);
        env->DeleteLocalRef(s);
    }
    return arr;
}

JNIEXPORT jlongArray JNICALL
Java_com_nex_peek_PeekNative_nativeGetInstructions(JNIEnv* env, jobject,
    jlong h, jlong fid, jint limit, jint offset) {
    if (!h) return env->NewLongArray(0);
    auto* ctx = reinterpret_cast<AnalysisContext*>(h);
    auto ins = ctx->db->get_instructions((int64_t)fid, limit, offset);
    jsize n = (jsize)(ins.size() * 2);
    jlongArray arr = env->NewLongArray(n);
    if (!n) return arr;
    std::vector<jlong> buf(n);
    for (size_t i = 0; i < ins.size(); ++i) {
        buf[i*2+0] = (jlong)ins[i].address;
        buf[i*2+1] = (jlong)ins[i].size;
    }
    env->SetLongArrayRegion(arr, 0, n, buf.data());
    return arr;
}

JNIEXPORT jobjectArray JNICALL
Java_com_nex_peek_PeekNative_nativeGetInstructionStrings(JNIEnv* env, jobject,
    jlong h, jlong fid, jint limit, jint offset) {
    jclass sc = env->FindClass("java/lang/String");
    if (!h) return env->NewObjectArray(0, sc, nullptr);
    auto* ctx = reinterpret_cast<AnalysisContext*>(h);
    auto ins = ctx->db->get_instructions((int64_t)fid, limit, offset);
    jsize n = (jsize)(ins.size() * 3);
    jobjectArray arr = env->NewObjectArray(n, sc, nullptr);
    for (size_t i = 0; i < ins.size(); ++i) {
        auto set = [&](jsize idx, const std::string& v) {
            jstring s = env->NewStringUTF(v.c_str());
            env->SetObjectArrayElement(arr, idx, s);
            env->DeleteLocalRef(s);
        };
        set((jsize)(i*3+0), ins[i].bytes_hex);
        set((jsize)(i*3+1), ins[i].mnemonic);
        set((jsize)(i*3+2), ins[i].operands);
    }
    return arr;
}

JNIEXPORT jlong JNICALL
Java_com_nex_peek_PeekNative_nativeGetInstructionCount(JNIEnv*, jobject,
    jlong h, jlong fid) {
    if (!h) return 0;
    return (jlong)reinterpret_cast<AnalysisContext*>(h)->db->get_instruction_count((int64_t)fid);
}

JNIEXPORT jlongArray JNICALL
Java_com_nex_peek_PeekNative_nativeGetXrefs(JNIEnv* env, jobject,
    jlong h, jlong address) {
    if (!h) return env->NewLongArray(0);
    auto* ctx = reinterpret_cast<AnalysisContext*>(h);
    if (ctx->binary_id < 0) return env->NewLongArray(0);
    auto xr = ctx->db->get_xrefs(ctx->binary_id, (uint64_t)address);
    jsize n = (jsize)(xr.size() * 2);
    jlongArray arr = env->NewLongArray(n);
    if (!n) return arr;
    std::vector<jlong> buf(n);
    for (size_t i = 0; i < xr.size(); ++i) {
        buf[i*2+0] = (jlong)xr[i].from_address;
        buf[i*2+1] = (jlong)xr[i].to_address;
    }
    env->SetLongArrayRegion(arr, 0, n, buf.data());
    return arr;
}

JNIEXPORT jobjectArray JNICALL
Java_com_nex_peek_PeekNative_nativeGetXrefTypes(JNIEnv* env, jobject,
    jlong h, jlong address) {
    jclass sc = env->FindClass("java/lang/String");
    if (!h) return env->NewObjectArray(0, sc, nullptr);
    auto* ctx = reinterpret_cast<AnalysisContext*>(h);
    if (ctx->binary_id < 0) return env->NewObjectArray(0, sc, nullptr);
    auto xr = ctx->db->get_xrefs(ctx->binary_id, (uint64_t)address);
    jobjectArray arr = env->NewObjectArray((jsize)xr.size(), sc, nullptr);
    for (size_t i = 0; i < xr.size(); ++i) {
        jstring s = env->NewStringUTF(xr[i].ref_type.c_str());
        env->SetObjectArrayElement(arr, (jsize)i, s);
        env->DeleteLocalRef(s);
    }
    return arr;
}

JNIEXPORT jlongArray JNICALL
Java_com_nex_peek_PeekNative_nativeGetSymbols(JNIEnv* env, jobject, jlong h) {
    if (!h) return env->NewLongArray(0);
    auto* ctx = reinterpret_cast<AnalysisContext*>(h);
    if (ctx->binary_id < 0) return env->NewLongArray(0);
    auto syms = ctx->db->get_symbols(ctx->binary_id);
    jsize n = (jsize)(syms.size() * 2);
    jlongArray arr = env->NewLongArray(n);
    if (!n) return arr;
    std::vector<jlong> buf(n);
    for (size_t i = 0; i < syms.size(); ++i) {
        buf[i*2+0] = (jlong)syms[i].address;
        buf[i*2+1] = syms[i].is_import ? 1L : 0L;
    }
    env->SetLongArrayRegion(arr, 0, n, buf.data());
    return arr;
}

JNIEXPORT jobjectArray JNICALL
Java_com_nex_peek_PeekNative_nativeGetSymbolStrings(JNIEnv* env, jobject, jlong h) {
    jclass sc = env->FindClass("java/lang/String");
    if (!h) return env->NewObjectArray(0, sc, nullptr);
    auto* ctx = reinterpret_cast<AnalysisContext*>(h);
    if (ctx->binary_id < 0) return env->NewObjectArray(0, sc, nullptr);
    auto syms = ctx->db->get_symbols(ctx->binary_id);
    jsize n = (jsize)(syms.size() * 2);
    jobjectArray arr = env->NewObjectArray(n, sc, nullptr);
    for (size_t i = 0; i < syms.size(); ++i) {
        auto set = [&](jsize idx, const std::string& v) {
            jstring s = env->NewStringUTF(v.c_str());
            env->SetObjectArrayElement(arr, idx, s);
            env->DeleteLocalRef(s);
        };
        set((jsize)(i*2+0), syms[i].name);
        set((jsize)(i*2+1), syms[i].type_str);
    }
    return arr;
}

JNIEXPORT jboolean JNICALL
Java_com_nex_peek_PeekNative_nativeInitDecompiler(JNIEnv* env, jobject,
                                                    jstring jspec_dir) {
    std::string spec_dir = jstr(env, jspec_dir);
    int ok = peek_decompiler_init(spec_dir.c_str());
    LOGI("Decompiler init: specDir=%s result=%d", spec_dir.c_str(), ok);
    return ok ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_com_nex_peek_PeekNative_nativeDecompileFunction(JNIEnv* env, jobject,
                                                       jlong h, jlong func_id) {
    if (!h) return env->NewStringUTF("");
    auto* ctx = reinterpret_cast<AnalysisContext*>(h);
    if (ctx->binary_id < 0) return env->NewStringUTF("");

    // Check cached pseudocode first.
    // The cache stores a version tag as the first line so stale entries
    // (produced before vtable/string resolution was added) are detected
    // and re-decompiled automatically.
    const char* CACHE_TAG    = JNI_ANNOTATOR_CACHE_TAG;
    const size_t CACHE_TAG_LEN = std::strlen(CACHE_TAG);
    {
        std::string cached = ctx->db->get_pseudocode((int64_t)func_id);
        if (!cached.empty()) {
            if (cached.size() >= CACHE_TAG_LEN &&
                cached.compare(0, CACHE_TAG_LEN, CACHE_TAG) == 0) {
                LOGI("Pseudocode cache hit funcId=%lld", (long long)func_id);
                return env->NewStringUTF(cached.c_str() + CACHE_TAG_LEN);
            }
            LOGI("Pseudocode cache stale (version mismatch) funcId=%lld — re-decompiling",
                 (long long)func_id);
        }
    }

    // Fetch function record from DB.
    DbFunction fn = ctx->db->get_function_by_id((int64_t)func_id);
    if (fn.id < 0) {
        LOGE("Function not found funcId=%lld", (long long)func_id);
        return env->NewStringUTF("");
    }

    // Re-parse ELF to obtain raw bytes for the function.
    ElfParseResult elf = elf_parse(ctx->file_path);
    if (!elf.ok) {
        LOGE("ELF re-parse failed: %s", elf.error.c_str());
        return env->NewStringUTF("");
    }

    // Use the Capstone-derived code end address so that Ghidra's followFlow
    // receives a tight [baddr, eaddr] that excludes any trailing literal pool
    // bytes.  fn.size is estimated as distance-to-next-function and often
    // includes non-instruction data at the end; those bytes would make
    // followFlow throw "Could not find op at target address" when a branch
    // lands in the data.  If the DB has no instructions for this function
    // (shouldn't happen, but be safe), fall back to fn.size.
    uint64_t code_end = ctx->db->get_code_end_address((int64_t)func_id);
    uint64_t code_len = (code_end > fn.address)
                            ? (code_end - fn.address)
                            : fn.size;
    // Never exceed the ELF-declared function size.
    if (code_len > fn.size) code_len = fn.size;
    LOGI("Decompiling %s addr=0x%llx fn.size=%llu code_len=%llu",
         fn.name.c_str(),
         (unsigned long long)fn.address,
         (unsigned long long)fn.size,
         (unsigned long long)code_len);

    const uint8_t* data = va_to_ptr(elf, fn.address, code_len);
    if (!data) {
        LOGE("va_to_ptr failed addr=0x%llx code_len=%llu",
             (unsigned long long)fn.address, (unsigned long long)code_len);
        return env->NewStringUTF("");
    }

    // Unique temp file per function to allow future parallelism.
    std::ostringstream tmp_ss;
    tmp_ss << ctx->tmp_dir << "/decomp_" << std::hex << (int64_t)func_id << ".bin";
    std::string tmp_path = tmp_ss.str();

    char* result_cstr = peek_decompile_bytes(
        data, (size_t)code_len, fn.name.c_str(), tmp_path.c_str(),
        (uint64_t)fn.address);

    if (!result_cstr) {
        const char* bridge_err = peek_decompile_get_last_error();
        LOGE("Decompile returned null for %s — %s", fn.name.c_str(), bridge_err);
        // Store the stage-specific error so the UI can surface it in debug builds
        // via nativeGetLastError().
        ctx->last_error = bridge_err ? bridge_err : "decompile bridge returned null";
        return env->NewStringUTF("");
    }

    std::string result(result_cstr);
    free(result_cstr);

    // 1. JNI-aware signature, param renames, vtable call resolution, and
    //    JNI constant naming.  No-op for non-JNI functions.
    result = jni_annotate(fn.name, result);

    // 2. ELF data-reference resolution: annotate xRam<addr> tokens with
    //    the string they point to, and annotate known JNI string arguments
    //    (FindClass, GetMethodID, etc.) whose value Ghidra shows as a hex VA.
    result = resolve_data_refs(result, elf);

    // 3. Store with a version tag so stale cache entries are auto-detected.
    ctx->db->store_pseudocode((int64_t)func_id, CACHE_TAG + result);
    LOGI("Decompiled %s (%zu chars)", fn.name.c_str(), result.size());

    return env->NewStringUTF(result.c_str());
}

} // extern "C"
