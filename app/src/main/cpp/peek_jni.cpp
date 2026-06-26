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
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
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

    // Persistent cross-function signature cache.
    // Loaded once from the DB after binary open; updated lazily as functions
    // are decompiled. Each entry maps to a PeekFuncSig record injected into
    // the Ghidra scope before followFlow on every decompile call.
    std::vector<FuncSignature> sig_cache;
    bool                     sigs_loaded = false;
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

    // Path 2: scan every SHT_RELA section for an entry whose r_offset == va.
    // We handle two cases:
    //   sym_idx == 0  (R_AARCH64_RELATIVE): r_addend is the target function VA.
    //   sym_idx  > 0  (R_AARCH64_ABS64, GLOB_DAT, …): look up the symbol name
    //                 directly from the .dynsym / .dynstr sections.
    for (const auto& sec : elf.sections) {
        if (sec.type != SHT_RELA) continue;
        const size_t entry_size = sizeof(Elf64_Rela);
        uint64_t n = sec.size / entry_size;
        for (uint64_t i = 0; i < n; ++i) {
            uint64_t off = sec.offset + i * entry_size;
            if (off + entry_size > elf.data.size()) break;
            const Elf64_Rela* r =
                reinterpret_cast<const Elf64_Rela*>(elf.data.data() + off);
            if (r->r_offset != va) continue;

            uint32_t sym_idx = ELF64_R_SYM(r->r_info);
            if (sym_idx == 0) {
                // No symbol — addend is the absolute function VA.
                std::string name = lookup_va_name(
                    elf, static_cast<uint64_t>(r->r_addend));
                if (!name.empty()) return name;
            } else {
                // Named-symbol relocation — read the name directly from
                // the raw .dynsym and .dynstr sections.
                const ParsedSection* dsym = nullptr;
                const ParsedSection* dstr = nullptr;
                for (const auto& s : elf.sections) {
                    if (s.type == SHT_DYNSYM && !dsym) dsym = &s;
                    if (s.type == SHT_STRTAB && s.name == ".dynstr" && !dstr) dstr = &s;
                }
                if (dsym && dstr) {
                    uint64_t soff = dsym->offset + sym_idx * sizeof(Elf64_Sym);
                    if (soff + sizeof(Elf64_Sym) <= elf.data.size()) {
                        const Elf64_Sym* sym = reinterpret_cast<const Elf64_Sym*>(
                            elf.data.data() + soff);
                        uint64_t noff = dstr->offset + sym->st_name;
                        if (sym->st_name < dstr->size && noff < elf.data.size()) {
                            std::string name(reinterpret_cast<const char*>(
                                elf.data.data() + noff));
                            if (!name.empty()) return name;
                        }
                    }
                }
                // Also try addend as VA fallback.
                if (r->r_addend != 0) {
                    std::string name = lookup_va_name(
                        elf, static_cast<uint64_t>(r->r_addend));
                    if (!name.empty()) return name;
                }
            }
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

// Resolve Ghidra data references and function call arguments INLINE.
//
// Pass 1 — *Ram<hex16>: Ghidra emits xRam/iRam/uRam/bRam/lRam/pRam<addr>
//   for any global memory access whose address is statically known.
//   Resolution order: C-string at addr → symbol name at addr → funcptr at addr.
//   If nothing resolves, the token is kept as-is.
//
// Pass 2 — JNI vtable string args: ->FindClass(env, 0x470e) etc.
//
// Pass 3 — direct call hex args: funcname(0xHEX, ...) where the hex value
//   falls inside a known ELF section.  Resolves to: "string" | &sym_name |
//   function_name.  Skips small constants (< 0x1000) and values outside any
//   mapped section so integer flags/sizes are never mis-annotated.
static std::string resolve_data_refs(const std::string& code,
                                      const ElfParseResult& elf) {
    // Pre-build addr→name map from symbols + functions (exclude sub_* / j_*).
    std::unordered_map<uint64_t, std::string> sym_map;
    for (const auto& sym : elf.symbols) {
        if (sym.address == 0 || sym.name.empty()) continue;
        if (sym.name.size() > 4 && sym.name[3] == '_' &&
            (sym.name[0] == 's' || sym.name[0] == 'j')) continue;
        sym_map.emplace(sym.address, sym.name);
    }
    for (const auto& fn : elf.functions) {
        if (fn.address == 0 || fn.name.empty()) continue;
        if (fn.name.size() > 4 && fn.name[3] == '_' &&
            (fn.name[0] == 's' || fn.name[0] == 'j')) continue;
        sym_map.emplace(fn.address, fn.name);  // prefer existing entry
    }

    // Section set for "is this VA in any mapped section?" used by Pass 3.
    struct SecRange { uint64_t base, end; bool exec; };
    std::vector<SecRange> sec_ranges;
    for (const auto& sec : elf.sections) {
        if (sec.size == 0 || sec.address == 0) continue;
        sec_ranges.push_back({sec.address, sec.address + sec.size,
                               sec.is_executable()});
    }
    auto va_section = [&](uint64_t va) -> const SecRange* {
        for (const auto& r : sec_ranges)
            if (va >= r.base && va < r.end) return &r;
        return nullptr;
    };

    // Resolve a single VA to the best printable representation.
    // Returns "" if nothing useful found.
    // data_prefix: prefix to emit before data symbol names (e.g. "&")
    auto resolve_va = [&](uint64_t va, bool allow_data_sym,
                           const char* data_prefix = "&") -> std::string {
        if (va < 0x100) return "";  // definitely an integer constant
        // 1. C string
        std::string s = elf_read_cstring(elf, va);
        if (!s.empty()) return "\"" + escape_for_literal(s) + "\"";
        // 2. Named symbol at this address
        auto it = sym_map.find(va);
        if (it != sym_map.end()) {
            const SecRange* sr = va_section(va);
            if (sr && sr->exec) return it->second;           // function name
            if (allow_data_sym) return std::string(data_prefix) + it->second;
        }
        // 3. Function pointer stored at this address (GOT/data slot)
        std::string fn = elf_resolve_funcptr(elf, va);
        if (!fn.empty()) return fn;
        return "";
    };

    // ---- Pass 1: *Ram<16-digit-hex> → resolved or kept as-is ------------
    std::string out;
    out.reserve(code.size());
    {
        size_t pos = 0;
        while (pos < code.size()) {
            // Look for "Ram" preceded by exactly one lowercase letter at a
            // word boundary — covers xRam/iRam/uRam/bRam/lRam/pRam/sRam.
            size_t f = code.find("Ram", pos);
            if (f == std::string::npos) { out.append(code, pos, std::string::npos); break; }

            // Must be preceded by a single lowercase letter at a word boundary.
            if (f < 1 || !std::islower((unsigned char)code[f-1])) {
                out.append(code, pos, f - pos + 1); pos = f + 1; continue;
            }
            size_t token_start = f - 1;
            if (token_start > 0 &&
                (std::isalnum((unsigned char)code[token_start-1]) || code[token_start-1]=='_')) {
                out.append(code, pos, f - pos + 1); pos = f + 1; continue;
            }

            // Read the 16 hex digits following "Ram".
            size_t p = f + 3;
            size_t hex_start = p;
            while (p < code.size() && std::isxdigit((unsigned char)code[p])) ++p;
            if (p - hex_start != 16) {
                out.append(code, pos, f - pos + 1); pos = f + 1; continue;
            }

            uint64_t va = std::strtoull(
                std::string(code, hex_start, 16).c_str(), nullptr, 16);

            std::string replacement = resolve_va(va, /*allow_data_sym=*/true, "");
            out.append(code, pos, token_start - pos);
            if (!replacement.empty()) {
                out += replacement;
            } else {
                // Keep the original *Ram<addr> token unchanged.
                out.append(code, token_start, p - token_start);
            }
            pos = p;
        }
    }

    // ---- Pass 2: JNI vtable string args 0x<hex> → "string" --------------
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
                    size_t hstart = p + 2;
                    size_t q = hstart;
                    while (q < out.size() && std::isxdigit((unsigned char)out[q])) ++q;
                    uint64_t va = std::strtoull(
                        std::string(out, hstart, q - hstart).c_str(), nullptr, 16);
                    std::string s = elf_read_cstring(elf, va);
                    if (!s.empty()) {
                        out2 += '"'; out2 += escape_for_literal(s); out2 += '"';
                    } else {
                        out2.append(out, p, q - p);
                    }
                    p = q;
                } else {
                    out2 += c; ++p;
                }
            }
            pos = p;
        }
    }

    // ---- Pass 3: hex literal args in direct function calls → names -------
    // Handles: funcname(0xhex, 0xhex, ...)
    // Only resolves hex values >= 0x1000 that fall inside a known ELF section.
    // This covers cases like:
    //   pthread_key_create(0xd3628, 0x6da30)  →  pthread_key_create(&g_key, dtor)
    //   __cxa_atexit(0x67cc4, 0xc0138, ...)   →  __cxa_atexit(cleanup, &g_ctx, ...)
    std::string out3;
    out3.reserve(out2.size());
    {
        size_t pos = 0;
        while (pos < out2.size()) {
            // Find an identifier followed immediately by '(' at word boundary.
            size_t id_start = pos;
            // Advance to next identifier-start character
            while (id_start < out2.size() &&
                   !std::isalpha((unsigned char)out2[id_start]) && out2[id_start] != '_')
                ++id_start;
            if (id_start >= out2.size()) {
                out3.append(out2, pos, std::string::npos);
                break;
            }

            // Must not be inside a ->method call (handled by Pass 2 already)
            // and must not be inside a (*ptr) expression.
            // Quick check: ensure char before id_start is not '>' or alnum/'_'
            // (the latter would mean we caught the tail of another identifier).
            bool bad_prefix = false;
            if (id_start > 0) {
                char prev = out2[id_start - 1];
                if (prev == '>' || std::isalnum((unsigned char)prev) || prev == '_')
                    bad_prefix = true;
            }
            if (bad_prefix) {
                out3.append(out2, pos, id_start - pos + 1);
                pos = id_start + 1;
                continue;
            }

            // Read identifier
            size_t id_end = id_start;
            while (id_end < out2.size() &&
                   (std::isalnum((unsigned char)out2[id_end]) || out2[id_end]=='_'))
                ++id_end;
            if (id_end >= out2.size() || out2[id_end] != '(') {
                out3.append(out2, pos, id_end - pos);
                pos = id_end;
                continue;
            }

            // Emit everything up to and including '('
            out3.append(out2, pos, id_end - pos + 1);
            pos = id_end + 1;

            // Parse arguments: resolve 0x<hex> args that are in-section addresses.
            int  paren_depth = 1;
            while (pos < out2.size() && paren_depth > 0) {
                char c = out2[pos];
                if (c == '(') { ++paren_depth; out3 += c; ++pos; continue; }
                if (c == ')') { --paren_depth; out3 += c; ++pos; continue; }
                if (c == '"') {
                    // Skip string literals untouched
                    out3 += c; ++pos;
                    while (pos < out2.size() && out2[pos] != '"') {
                        if (out2[pos] == '\\') { out3 += out2[pos++]; }
                        out3 += out2[pos++];
                    }
                    if (pos < out2.size()) { out3 += out2[pos++]; }
                    continue;
                }
                // Look for 0x<hex> at argument position (depth==1)
                if (paren_depth == 1 && c == '0' &&
                    pos + 1 < out2.size() &&
                    (out2[pos+1] == 'x' || out2[pos+1] == 'X')) {
                    size_t hstart = pos + 2;
                    size_t q = hstart;
                    while (q < out2.size() && std::isxdigit((unsigned char)out2[q])) ++q;
                    size_t hex_digits = q - hstart;
                    uint64_t va = std::strtoull(
                        std::string(out2, hstart, hex_digits).c_str(), nullptr, 16);

                    // Only resolve if large enough to be an address AND in a section.
                    bool emitted = false;
                    if (va >= 0x1000 && hex_digits >= 4 && va_section(va)) {
                        const SecRange* sr = va_section(va);
                        // For code-section VAs: emit function name directly.
                        // For data-section VAs: emit &sym_name or "string".
                        std::string resolved = resolve_va(
                            va, /*allow_data_sym=*/true,
                            sr && sr->exec ? "" : "&");
                        if (!resolved.empty()) {
                            out3 += resolved;
                            emitted = true;
                        }
                    }
                    if (!emitted) out3.append(out2, pos, q - pos);
                    pos = q;
                    continue;
                }
                out3 += c; ++pos;
            }
        }
    }

    return out3;
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

// Scan executable sections for ARM64 function prologues. Two idioms:
//   (A) sub sp, sp, #N   followed immediately by   stp x29, x30, [sp, #M]
//   (B) stp x29, x30, [sp, #-N]!   (pre-index form; folds the sp adjustment
//       into the stp itself, so there's no separate "sub sp" instruction)
// Any match that is not already in func_map gets added with an empty name
// (will be auto-named sub_ADDRESS later).
static void prologue_scan(const ElfParseResult& elf,
                           std::map<uint64_t, std::string>& func_map) {
    for (const auto& sec : elf.sections) {
        if (!sec.is_executable() || sec.size < 4) continue;
        const uint8_t* base = elf.data.data() + sec.offset;

        for (uint64_t off = 0; off + 4 <= sec.size; off += 4) {
            uint32_t w0;
            std::memcpy(&w0, base + off, 4);

            // (B) stp x29, x30, [sp, #-N]! — pre-index, self-contained.
            // Fixed register fields: Rt1=x29(29), Rn=sp(31), Rt2=x30(30) → 0x7BFD.
            bool is_stp_preindex = (w0 & 0xFFC07FFF) == 0xA9807BFD;
            if (is_stp_preindex) {
                func_map.emplace(sec.address + off, "");
                continue;
            }

            // (A) sub sp, sp, #N — must be followed by a signed-offset stp.
            if (off + 8 > sec.size) continue;
            uint32_t w1;
            std::memcpy(&w1, base + off + 4, 4);

            // sub sp, sp, #imm (64-bit): sf=1 op=1 S=0 100010 0 Rn=31 Rd=31
            bool is_sub_sp = (w0 & 0xFF8003FF) == 0xD10003FF;
            // stp x29, x30, [sp, #N] — signed-offset form.
            bool is_stp_signed = (w1 & 0xFFC07FFF) == 0xA9007BFD;

            if (is_sub_sp && is_stp_signed) {
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
// where known, then explicitly-known sizes (e.g. thunks pinned during
// discovery), and falling back to estimate_size otherwise.
static std::vector<FuncEntry> build_entries(
    const std::map<uint64_t, std::string>& fm,
    const ElfParseResult& elf,
    uint64_t code_base, uint64_t code_end,
    const std::map<uint64_t, uint64_t>& known_sizes = {})
{
    std::vector<FuncEntry> out;
    out.reserve(fm.size());
    for (const auto& [addr, name] : fm) {
        if (addr == 0 || addr < code_base || addr >= code_end) continue;

        uint64_t sz = 0;
        for (const auto& fn : elf.functions) {
            if (fn.address == addr && fn.size > 0) { sz = fn.size; break; }
        }
        if (sz == 0) {
            auto ks = known_sizes.find(addr);
            if (ks != known_sizes.end()) sz = ks->second;
        }
        if (sz == 0) sz = estimate_size(addr, fm, code_end);
        if (sz == 0) continue;

        out.push_back({addr, sz, name.empty() ? sub_name(addr) : name});
    }
    return out;
}

// ---------------------------------------------------------------------------
// Built-in stdlib / libc / C++ runtime prototype table
//
// Source: well-known AArch64/AAPCS64 signatures for the most common runtime
// functions.  These are applied on top of symbol-derived records so callers
// always get correct prototypes even when the ELF has stripped symbols.
//
// Type vocabulary: void / bool / int / uint / long / ulong / float / double /
//   ptr (= void*) / void* / char* / size_t / unknown
// ---------------------------------------------------------------------------

struct StdlibProto {
    const char* name;
    const char* return_type;
    int         param_count;
    const char* params_csv;
};

static const StdlibProto kStdlibProtos[] = {
    // --- memory ---
    { "malloc",        "void*",  1, "size_t"                       },
    { "calloc",        "void*",  2, "size_t,size_t"                },
    { "realloc",       "void*",  2, "void*,size_t"                 },
    { "free",          "void",   1, "void*"                        },
    { "aligned_alloc", "void*",  2, "size_t,size_t"                },
    { "mmap",          "void*",  6, "void*,size_t,int,int,int,long"},
    { "munmap",        "int",    2, "void*,size_t"                 },
    { "memcpy",        "void*",  3, "void*,void*,size_t"           },
    { "memmove",       "void*",  3, "void*,void*,size_t"           },
    { "memset",        "void*",  3, "void*,int,size_t"             },
    { "memcmp",        "int",    3, "void*,void*,size_t"           },
    { "memchr",        "void*",  3, "void*,int,size_t"             },
    { "bzero",         "void",   2, "void*,size_t"                 },
    // --- string ---
    { "strlen",        "size_t", 1, "char*"                        },
    { "strnlen",       "size_t", 2, "char*,size_t"                 },
    { "strcmp",        "int",    2, "char*,char*"                  },
    { "strncmp",       "int",    3, "char*,char*,size_t"           },
    { "strcasecmp",    "int",    2, "char*,char*"                  },
    { "strncasecmp",   "int",    3, "char*,char*,size_t"           },
    { "strcpy",        "char*",  2, "char*,char*"                  },
    { "strncpy",       "char*",  3, "char*,char*,size_t"           },
    { "strcat",        "char*",  2, "char*,char*"                  },
    { "strncat",       "char*",  3, "char*,char*,size_t"           },
    { "strchr",        "char*",  2, "char*,int"                    },
    { "strrchr",       "char*",  2, "char*,int"                    },
    { "strstr",        "char*",  2, "char*,char*"                  },
    { "strtok",        "char*",  2, "char*,char*"                  },
    { "strtol",        "long",   3, "char*,ptr,int"                },
    { "strtoul",       "ulong",  3, "char*,ptr,int"                },
    { "strtoll",       "long",   3, "char*,ptr,int"                },
    { "strtoull",      "ulong",  3, "char*,ptr,int"                },
    { "strtod",        "double", 2, "char*,ptr"                    },
    { "strtof",        "float",  2, "char*,ptr"                    },
    { "snprintf",      "int",    3, "char*,size_t,char*"           },
    { "sprintf",       "int",    2, "char*,char*"                  },
    { "printf",        "int",    1, "char*"                        },
    { "fprintf",       "int",    2, "ptr,char*"                    },
    { "vsnprintf",     "int",    4, "char*,size_t,char*,ptr"       },
    { "vsprintf",      "int",    3, "char*,char*,ptr"              },
    { "sscanf",        "int",    2, "char*,char*"                  },
    // --- I/O ---
    { "fopen",         "ptr",    2, "char*,char*"                  },
    { "fclose",        "int",    1, "ptr"                          },
    { "fread",         "size_t", 4, "void*,size_t,size_t,ptr"      },
    { "fwrite",        "size_t", 4, "void*,size_t,size_t,ptr"      },
    { "fseek",         "int",    3, "ptr,long,int"                 },
    { "ftell",         "long",   1, "ptr"                          },
    { "fflush",        "int",    1, "ptr"                          },
    { "fgets",         "char*",  3, "char*,int,ptr"                },
    { "fputs",         "int",    2, "char*,ptr"                    },
    { "fgetc",         "int",    1, "ptr"                          },
    { "fputc",         "int",    2, "int,ptr"                      },
    { "open",          "int",    2, "char*,int"                    },
    { "read",          "long",   3, "int,void*,size_t"             },
    { "write",         "long",   3, "int,void*,size_t"             },
    { "close",         "int",    1, "int"                          },
    // --- process / env ---
    { "exit",          "void",   1, "int"                          },
    { "abort",         "void",   0, ""                             },
    { "getenv",        "char*",  1, "char*"                        },
    { "putenv",        "int",    1, "char*"                        },
    { "system",        "int",    1, "char*"                        },
    { "fork",          "int",    0, ""                             },
    { "execve",        "int",    3, "char*,ptr,ptr"                },
    { "waitpid",       "int",    3, "int,ptr,int"                  },
    // --- math ---
    { "abs",           "int",    1, "int"                          },
    { "labs",          "long",   1, "long"                         },
    { "llabs",         "long",   1, "long"                         },
    { "pow",           "double", 2, "double,double"                },
    { "sqrt",          "double", 1, "double"                       },
    { "floor",         "double", 1, "double"                       },
    { "ceil",          "double", 1, "double"                       },
    { "fabs",          "double", 1, "double"                       },
    { "sin",           "double", 1, "double"                       },
    { "cos",           "double", 1, "double"                       },
    { "log",           "double", 1, "double"                       },
    { "log2",          "double", 1, "double"                       },
    { "log10",         "double", 1, "double"                       },
    // --- C++ runtime ---
    { "_Znwm",         "void*",  1, "size_t"                       }, // operator new(size_t)
    { "_Znam",         "void*",  1, "size_t"                       }, // operator new[](size_t)
    { "_ZdlPv",        "void",   1, "void*"                        }, // operator delete(void*)
    { "_ZdaPv",        "void",   1, "void*"                        }, // operator delete[](void*)
    { "_ZdlPvm",       "void",   2, "void*,size_t"                 }, // operator delete(void*,size_t)
    { "__cxa_throw",   "void",   3, "void*,void*,void*"            },
    { "__cxa_allocate_exception", "void*", 1, "size_t"             },
    { "__cxa_begin_catch",  "void*",  1, "void*"                   },
    { "__cxa_end_catch",    "void",   0, ""                        },
    { "__cxa_guard_acquire","int",    1, "ptr"                      },
    { "__cxa_guard_release","void",   1, "ptr"                      },
    // --- pthread ---
    { "pthread_create",  "int",  4, "ptr,ptr,ptr,void*"            },
    { "pthread_join",    "int",  2, "ulong,ptr"                    },
    { "pthread_mutex_lock",   "int", 1, "ptr"                      },
    { "pthread_mutex_unlock", "int", 1, "ptr"                      },
    { "pthread_mutex_init",   "int", 2, "ptr,ptr"                  },
    { "pthread_mutex_destroy","int", 1, "ptr"                      },
    // --- Android-specific ---
    { "__android_log_print", "int", 3, "int,char*,char*"           },
    { "__android_log_write", "int", 3, "int,char*,char*"           },
    { "AAssetManager_fromJava", "ptr", 2, "ptr,ptr"                },
    { "AAsset_read",     "int",  3, "ptr,void*,size_t"             },
    { "AAsset_close",    "void", 1, "ptr"                          },
};
static const size_t kStdlibProtoCount =
    sizeof(kStdlibProtos) / sizeof(kStdlibProtos[0]);

// Build a name→proto map for O(1) lookup during signature population.
static std::unordered_map<std::string, const StdlibProto*> g_stdlib_map;
static std::once_flag g_stdlib_map_flag;

static void ensure_stdlib_map() {
    std::call_once(g_stdlib_map_flag, []() {
        for (size_t i = 0; i < kStdlibProtoCount; ++i)
            g_stdlib_map[kStdlibProtos[i].name] = &kStdlibProtos[i];
    });
}

// ---------------------------------------------------------------------------
// Signature cache management
//
// populate_sig_cache() builds the per-binary FuncSignature vector from:
//   1. All functions discovered in run_analysis (name + address only)
//   2. All symbols (name + address only)
//   3. stdlib overrides — apply known prototypes whenever a function's name
//      matches a stdlib entry (strips any leading "j_" thunk prefix first)
//
// The result is stored in the DB (func_signatures table) for persistence and
// also kept in ctx.sig_cache for use throughout the session.
// ---------------------------------------------------------------------------

static void populate_sig_cache(AnalysisContext& ctx,
                                const ElfParseResult& elf)
{
    if (ctx.binary_id < 0) return;
    ensure_stdlib_map();

    // Build a map: address → FuncSignature (for deduplication).
    std::map<uint64_t, FuncSignature> sigmap;

    // --- Source 1: ELF-discovered functions (names from symbol table) ---
    for (const auto& fn : elf.functions) {
        if (fn.address == 0 || fn.name.empty()) continue;
        FuncSignature s;
        s.address = fn.address;
        s.name    = fn.name;
        s.source  = "symbol";
        sigmap[fn.address] = std::move(s);
    }

    // --- Source 2: ELF symbols (may add entries not in elf.functions) ---
    for (const auto& sym : elf.symbols) {
        if (sym.address == 0 || sym.name.empty()) continue;
        if (sigmap.count(sym.address)) continue;  // function already added
        FuncSignature s;
        s.address = sym.address;
        s.name    = sym.name;
        s.source  = "symbol";
        sigmap[sym.address] = std::move(s);
    }

    // --- Source 3: apply stdlib prototypes where name matches ---
    for (auto& [addr, sig] : sigmap) {
        // Strip thunk prefix for lookup ("j_malloc" → "malloc").
        std::string lookup_name = sig.name;
        if (lookup_name.size() > 2 &&
            lookup_name[0] == 'j' && lookup_name[1] == '_')
            lookup_name = lookup_name.substr(2);

        auto it = g_stdlib_map.find(lookup_name);
        if (it != g_stdlib_map.end()) {
            const StdlibProto* p = it->second;
            sig.return_type = p->return_type ? p->return_type : "";
            sig.param_count = p->param_count;
            sig.params_csv  = p->params_csv ? p->params_csv : "";
            sig.source      = "stdlib";
        }
    }

    // Build vector and persist to DB in one batch.
    std::vector<FuncSignature> sigs;
    sigs.reserve(sigmap.size());
    for (auto& [addr, sig] : sigmap)
        sigs.push_back(std::move(sig));

    ctx.db->store_signatures(ctx.binary_id, sigs);
    ctx.sig_cache   = sigs;
    ctx.sigs_loaded = true;

    LOGI("Signature cache: %zu entries for binary_id=%lld",
         sigs.size(), (long long)ctx.binary_id);
}

// Ensure the sig_cache is populated (load from DB if not yet done).
// Called on every decompile request to handle the case where the binary
// was already in the DB cache (run_analysis was skipped).
static void ensure_sigs_loaded(AnalysisContext& ctx) {
    if (ctx.sigs_loaded) return;
    if (ctx.binary_id < 0) return;

    ctx.sig_cache   = ctx.db->get_signatures(ctx.binary_id);
    ctx.sigs_loaded = true;

    // If the DB has no signatures yet (binary opened from cache without
    // run_analysis, or very old DB entry), re-parse the ELF and populate.
    if (ctx.sig_cache.empty()) {
        LOGI("No signatures in DB for binary_id=%lld — populating from ELF",
             (long long)ctx.binary_id);
        ElfParseResult elf = elf_parse(ctx.file_path);
        if (elf.ok) {
            populate_sig_cache(ctx, elf);
        }
    }

    LOGI("Loaded %zu signatures from DB for binary_id=%lld",
         ctx.sig_cache.size(), (long long)ctx.binary_id);
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

    // Seed the ELF entry point (e_entry) as "start", matching IDA/Ghidra
    // convention. The entry point is rarely covered by a symbol of its own
    // (it's compiler-generated init code, not a named function) and nothing
    // else in this pipeline ever looks at ehdr->e_entry, so without this it
    // silently never appears anywhere in the function list.
    if (elf.data.size() >= sizeof(Elf64_Ehdr)) {
        auto* ehdr = reinterpret_cast<const Elf64_Ehdr*>(elf.data.data());
        if (ehdr->e_entry != 0 && !func_map.count(ehdr->e_entry)) {
            func_map[ehdr->e_entry] = "start";
        }
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

    // thunk_naming_pass() labels a single func_map entry as a thunk (j_<name>)
    // if its disassembly matches a direct "b #target" or PLT-style
    // "adrp+ldr+br" jumpout pattern. Used both for Phase-1/2 functions
    // (below) and for PLT stubs first discovered as call targets in
    // Phase 4 (which have no symbol of their own and are disassembled
    // for the first time there — see "Phase 4.5" further down).
    auto thunk_naming_pass = [&](uint64_t addr, std::string& name,
                                  const std::vector<DisasmInstruction>& insns) {
        if (insns.empty() || insns.size() > 5) return;   // thunks are tiny

        const auto& last = insns.back();

        // ── Case A: direct unconditional branch "b #target" ──────────────────
        if (last.mnemonic == "b") {
            uint64_t target = 0;
            if (!parse_hex_imm(last.operands.c_str(), target) || target == addr)
                return;
            auto tgt_it = func_map.find(target);
            std::string base = (tgt_it != func_map.end() && !tgt_it->second.empty())
                               ? tgt_it->second : sub_name(target);
            name = (base.size() >= 2 && base.substr(0, 2) == "j_") ? base : "j_" + base;
            LOGI("Direct thunk 0x%llx → %s", (unsigned long long)addr, name.c_str());
            return;
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

            if (!found_adrp || !found_ldr) return;

            uint64_t got_va = adrp_page + ldr_off;
            auto got_it = got_to_sym.find(got_va);
            if (got_it == got_to_sym.end()) return;

            name = "j_" + got_it->second;
            LOGI("PLT thunk 0x%llx → %s (GOT 0x%llx)",
                 (unsigned long long)addr, name.c_str(), (unsigned long long)got_va);
        }
    };

    for (auto& [addr, name] : func_map) {
        if (!name.empty()) continue;   // don't override a meaningful name (e.g. "start")
        auto it = disasm_cache.find(addr);
        if (it == disasm_cache.end()) continue;
        thunk_naming_pass(addr, name, it->second);
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

    // --- Phase 4.5: thunk-naming for Phase-4 discoveries (e.g. PLT stubs
    // called directly without a dedicated jumpout wrapper) ---
    //   These addresses have no ELF symbol and were never disassembled in
    //   Phase 3 (they weren't in func_map yet), so disasm_cache has no entry
    //   for them. Disassemble each one now and run the same thunk-naming
    //   pass used above — this is what lets a bare PLT entry (e.g. the
    //   "adrp+ldr+add+br" stub at the call site of an imported libc
    //   function) be correctly renamed to j_<importname> and tagged as a
    //   thunk (kind=2) instead of showing up as an unnamed sub_<addr> with
    //   un-decompilable trampoline bytes.
    //
    //   We also pin the exact probed size for each renamed thunk in
    //   thunk_sizes. Without this, Phase 5's build_entries() falls back to
    //   estimate_size(), which measures distance to the *next func_map
    //   entry* — and since unreferenced PLT stubs in between (e.g. ones
    //   nothing in .text calls directly) are never added to func_map at
    //   all, that distance can overshoot through several unclaimed PLT
    //   slots and into the next real function, producing a wildly
    //   oversized "thunk" that swallows real code.
    std::map<uint64_t, uint64_t> thunk_sizes;
    for (auto& [addr, name] : func_map) {
        if (!name.empty()) continue;               // already named/handled
        if (disasm_cache.count(addr)) continue;     // already disassembled in Phase 3

        // Probe length = distance to the next known func_map entry, capped
        // to a small thunk-sized window. A fixed constant either truncates
        // a thunk early or, worse, overshoots into the next PLT entry and
        // shifts the real terminating br/b instruction off the end of the
        // list that thunk_naming_pass inspects via insns.back(). 16 bytes
        // covers the largest case we handle (adrp+ldr+add+br); estimate_size
        // already won't exceed the gap to the next entry.
        uint64_t probe_len = std::min<uint64_t>(estimate_size(addr, func_map, code_end), 16);
        if (probe_len == 0) continue;
        const uint8_t* data = va_to_ptr(elf, addr, probe_len);
        if (!data) continue;
        DisasmResult dr = disassemble_arm64(data, (size_t)probe_len, addr);
        if (!dr.ok || dr.instructions.empty()) continue;

        disasm_cache[addr] = dr.instructions;
        thunk_naming_pass(addr, name, dr.instructions);

        // Only pin a size if naming actually succeeded (name is non-empty
        // afterward); an un-recognized stub falls through to sub_<addr>
        // with the normal estimate_size() behavior, same as before.
        if (!name.empty()) {
            // Real stub length = bytes actually consumed up to and
            // including the terminating br/b instruction, not the full
            // probe window (which may include trailing bytes from the
            // capped gap that aren't part of this stub).
            uint64_t real_len = dr.instructions.back().address
                               + dr.instructions.back().size - addr;
            thunk_sizes[addr] = std::min(real_len, probe_len);
        }
    }

    // --- Phase 5: build final function list and store everything ---
    auto all_entries = build_entries(func_map, elf, code_base, code_end, thunk_sizes);
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

    // Build and persist the cross-function signature cache from the freshly
    // analysed ELF.  This only runs for new binaries; cache-hit binaries load
    // signatures from the DB lazily on first decompile (ensure_sigs_loaded).
    populate_sig_cache(ctx, elf);

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

    // Thunks (kind==2, e.g. j_malloc) are PLT trampolines: a handful of
    // adrp/ldr/add/br instructions that jump to an externally-resolved
    // import. There is no real logic to decompile — running Ghidra's
    // p-code pipeline on the trampoline bytes either errors out or
    // produces meaningless output. Synthesize a one-line stub instead,
    // mirroring how Ghidra/IDA render thunks to externals.
    if (fn.kind == 2) {
        std::string import_name = fn.name;
        if (import_name.size() >= 2 && import_name[0] == 'j' && import_name[1] == '_')
            import_name = import_name.substr(2);
        std::string stub = "// thunk -> external import\nvoid " + fn.name +
                            "(void) {\n    " + import_name + "();\n}\n";
        ctx->db->store_pseudocode((int64_t)func_id, CACHE_TAG + stub);
        return env->NewStringUTF(stub.c_str());
    }

    // Ensure the cross-function signature cache is loaded.  For binaries that
    // were already in the DB cache (run_analysis skipped), signatures are read
    // from the DB here on first decompile rather than at binary-open time.
    ensure_sigs_loaded(*ctx);

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
    LOGI("Decompiling %s addr=0x%llx fn.size=%llu code_len=%llu sigs=%zu",
         fn.name.c_str(),
         (unsigned long long)fn.address,
         (unsigned long long)fn.size,
         (unsigned long long)code_len,
         ctx->sig_cache.size());

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

    // Build the flat C-struct array that peek_decompile_bytes_v2 accepts.
    // We keep the strings alive in sig_cache (which owns them) — the PeekFuncSig
    // pointers are valid for the duration of this call.
    std::vector<PeekFuncSig> c_sigs;
    c_sigs.reserve(ctx->sig_cache.size());
    for (const auto& s : ctx->sig_cache) {
        if (s.address == fn.address) continue;  // skip self
        PeekFuncSig cs;
        cs.address     = s.address;
        cs.name        = s.name.c_str();
        cs.return_type = s.return_type.empty() ? nullptr : s.return_type.c_str();
        cs.param_count = s.param_count;
        cs.params_csv  = s.params_csv.empty() ? nullptr : s.params_csv.c_str();
        c_sigs.push_back(cs);
    }

    PeekInferredSig inferred = {};
    char* result_cstr = peek_decompile_bytes_v2(
        data, (size_t)code_len,
        fn.name.c_str(), tmp_path.c_str(), (uint64_t)fn.address,
        c_sigs.empty() ? nullptr : c_sigs.data(), c_sigs.size(),
        &inferred);

    if (!result_cstr) {
        const char* bridge_err = peek_decompile_get_last_error();
        LOGE("Decompile returned null for %s — %s", fn.name.c_str(), bridge_err);
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

    // 4. Lazy learning — if the decompiler inferred a prototype for this
    //    function, store it in the signature cache and DB so future callers
    //    (functions that call this one) benefit from the improved types.
    if (inferred.is_set) {
        // Only update if we don't already have a high-trust entry for this
        // function (stdlib entries have already been applied at populate time).
        bool already_good = false;
        for (const auto& s : ctx->sig_cache) {
            if (s.address == fn.address &&
                (s.source == "stdlib" || s.source == "il2cpp")) {
                already_good = true;
                break;
            }
        }
        if (!already_good) {
            FuncSignature infsig;
            infsig.address     = fn.address;
            infsig.name        = fn.name;
            infsig.return_type = inferred.return_type;
            infsig.params_csv  = inferred.params_csv;
            infsig.param_count = inferred.param_count;
            infsig.source      = "inferred";

            // Update or insert in the in-memory cache.
            bool found = false;
            for (auto& s : ctx->sig_cache) {
                if (s.address == fn.address) {
                    s = infsig;
                    found = true;
                    break;
                }
            }
            if (!found) ctx->sig_cache.push_back(infsig);

            // Persist to DB.
            ctx->db->store_signature(ctx->binary_id, infsig);

            LOGI("Stored inferred sig for %s → %s(%s)",
                 fn.name.c_str(),
                 infsig.return_type.c_str(),
                 infsig.params_csv.c_str());
        }
    }

    return env->NewStringUTF(result.c_str());
}

} // extern "C"
