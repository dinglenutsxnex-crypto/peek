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

#include "algo_detector.h"
#include "elf_parser.h"
#include "disassembler.h"
#include "xref_detector.h"
#include "db_cache.h"
#include "decompiler_bridge.h"
#include "jni_annotator.h"
#include "il2cpp_metadata.h"

#include <jni.h>
#include <android/log.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <setjmp.h>
#include <signal.h>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#define TAG "PeekJNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ---------------------------------------------------------------------------
// Decompiler SIGSEGV guard
//
// Ghidra's decompiler library can produce a SIGSEGV on functions containing
// instructions whose P-code tables have incomplete/null sub-constructors
// (e.g. ARMv8.1 LSE atomics, certain extended-register encodings). Because
// the crash happens inside a pre-compiled native library, it cannot be caught
// by C++ try/catch — only a signal handler can intercept it.
//
// Strategy: before each peek_decompile_elf call, temporarily replace
// the existing SIGSEGV handler with a guard that calls siglongjmp back to
// the established recovery point.  On recovery we log the incident, skip
// the pseudocode for that function, and restore the original handler so the
// crash-reporting path (crash_handler.cpp) remains intact for genuine crashes
// that happen outside of decompilation.
//
// Thread-safety: both fields are thread_local — decompilation jobs run on
// the IO thread, but if the app ever parallelises them each thread has its
// own independent recovery state.
// ---------------------------------------------------------------------------

static thread_local sigjmp_buf  g_decomp_jmp;
static thread_local volatile bool g_decomp_active = false;

static void decomp_segv_guard(int sig, siginfo_t* /*info*/, void* /*ctx*/) {
    if (g_decomp_active) {
        g_decomp_active = false;
        siglongjmp(g_decomp_jmp, 1);
    }
    // Not in a guarded decompile call — re-raise so the real crash handler
    // (crash_handler.cpp) takes over and writes the diagnostic file.
    signal(sig, SIG_DFL);
    raise(sig);
}

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

    // Set when the binary was opened via the Unity path (IL2CPP dump).
    bool                     is_unity    = false;
    std::string              il2cpp_log;   // diagnostic log from il2cpp_dump()
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
// Pass 1 — *Ram<hex16>: Ghidra emits xRam/iRam/uRam/bRam/lRam/pRam/sRam<addr>
//   and also multi-char prefix variants pcRam/puRam/plRam/pbRam/psRam/paRam
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

            // Must be preceded by one or more lowercase letters at a word
            // boundary.  Walk back past the full lowercase prefix so we catch
            // both single-char (xRam, pRam) and two-char (pcRam, puRam, plRam,
            // pbRam, psRam, paRam) Ghidra type-prefix variants.
            if (f < 1 || !std::islower((unsigned char)code[f-1])) {
                out.append(code, pos, f - pos + 1); pos = f + 1; continue;
            }
            size_t token_start = f - 1;
            while (token_start > 0 && std::islower((unsigned char)code[token_start - 1]))
                --token_start;
            // Word boundary: char before the prefix must not be identifier char.
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
                // Nothing resolved: emit unk_<addr> (IDA-style, no leading
                // zeros) — far more readable than the raw 20-char token.
                char short_buf[32];
                snprintf(short_buf, sizeof(short_buf), "unk_%llx",
                         (unsigned long long)va);
                out += short_buf;
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
    // --- C stdlib extras ---
    { "atoi",          "int",    1, "char*"                        },
    { "atol",          "long",   1, "char*"                        },
    { "atoll",         "long",   1, "char*"                        },
    { "atof",          "double", 1, "char*"                        },
    { "strdup",        "char*",  1, "char*"                        },
    { "strndup",       "char*",  2, "char*,size_t"                 },
    { "strsep",        "char*",  2, "ptr,char*"                    },
    { "strpbrk",       "char*",  2, "char*,char*"                  },
    { "strspn",        "size_t", 2, "char*,char*"                  },
    { "strcspn",       "size_t", 2, "char*,char*"                  },
    { "strtok_r",      "char*",  3, "char*,char*,ptr"              },
    { "strerror",      "char*",  1, "int"                          },
    { "perror",        "void",   1, "char*"                        },
    { "qsort",         "void",   4, "void*,size_t,size_t,ptr"      },
    { "bsearch",       "void*",  5, "void*,void*,size_t,size_t,ptr"},
    { "rand",          "int",    0, ""                             },
    { "rand_r",        "int",    1, "ptr"                          },
    { "srand",         "void",   1, "uint"                         },
    { "random",        "long",   0, ""                             },
    { "srandom",       "void",   1, "uint"                         },
    { "arc4random",    "uint",   0, ""                             },
    { "arc4random_uniform","uint",1,"uint"                         },
    // --- ctype ---
    { "isalpha",       "int",    1, "int"                          },
    { "isdigit",       "int",    1, "int"                          },
    { "isalnum",       "int",    1, "int"                          },
    { "isspace",       "int",    1, "int"                          },
    { "isprint",       "int",    1, "int"                          },
    { "ispunct",       "int",    1, "int"                          },
    { "iscntrl",       "int",    1, "int"                          },
    { "isupper",       "int",    1, "int"                          },
    { "islower",       "int",    1, "int"                          },
    { "toupper",       "int",    1, "int"                          },
    { "tolower",       "int",    1, "int"                          },
    // --- time ---
    { "time",          "long",   1, "ptr"                          },
    { "clock",         "long",   0, ""                             },
    { "clock_gettime", "int",    2, "int,ptr"                      },
    { "gettimeofday",  "int",    2, "ptr,ptr"                      },
    { "nanosleep",     "int",    2, "ptr,ptr"                      },
    { "usleep",        "int",    1, "uint"                         },
    { "sleep",         "uint",   1, "uint"                         },
    { "localtime",     "ptr",    1, "ptr"                          },
    { "gmtime",        "ptr",    1, "ptr"                          },
    { "mktime",        "long",   1, "ptr"                          },
    { "strftime",      "size_t", 4, "char*,size_t,char*,ptr"       },
    // --- file / dir ---
    { "stat",          "int",    2, "char*,ptr"                    },
    { "fstat",         "int",    2, "int,ptr"                      },
    { "lstat",         "int",    2, "char*,ptr"                    },
    { "access",        "int",    2, "char*,int"                    },
    { "getcwd",        "char*",  2, "char*,size_t"                 },
    { "chdir",         "int",    1, "char*"                        },
    { "mkdir",         "int",    2, "char*,uint"                   },
    { "rmdir",         "int",    1, "char*"                        },
    { "unlink",        "int",    1, "char*"                        },
    { "rename",        "int",    2, "char*,char*"                  },
    { "opendir",       "ptr",    1, "char*"                        },
    { "readdir",       "ptr",    1, "ptr"                          },
    { "closedir",      "int",    1, "ptr"                          },
    { "realpath",      "char*",  2, "char*,char*"                  },
    // --- memory map / protection ---
    { "mprotect",      "int",    3, "void*,size_t,int"             },
    { "mlock",         "int",    2, "void*,size_t"                 },
    { "munlock",       "int",    2, "void*,size_t"                 },
    { "msync",         "int",    3, "void*,size_t,int"             },
    { "mremap",        "void*",  5, "void*,size_t,size_t,int,void*"},
    { "mincore",       "int",    3, "void*,size_t,ptr"             },
    { "madvise",       "int",    3, "void*,size_t,int"             },
    // --- dynamic linker ---
    { "dlopen",        "void*",  2, "char*,int"                    },
    { "dlclose",       "int",    1, "void*"                        },
    { "dlsym",         "void*",  2, "void*,char*"                  },
    { "dladdr",        "int",    2, "void*,ptr"                    },
    { "dlerror",       "char*",  0, ""                             },
    // --- networking ---
    { "socket",        "int",    3, "int,int,int"                  },
    { "bind",          "int",    3, "int,ptr,uint"                 },
    { "connect",       "int",    3, "int,ptr,uint"                 },
    { "listen",        "int",    2, "int,int"                      },
    { "accept",        "int",    3, "int,ptr,ptr"                  },
    { "send",          "long",   4, "int,void*,size_t,int"         },
    { "recv",          "long",   4, "int,void*,size_t,int"         },
    { "sendto",        "long",   6, "int,void*,size_t,int,ptr,uint"},
    { "recvfrom",      "long",   6, "int,void*,size_t,int,ptr,ptr" },
    { "setsockopt",    "int",    5, "int,int,int,void*,uint"       },
    { "getsockopt",    "int",    5, "int,int,int,void*,ptr"        },
    { "shutdown",      "int",    2, "int,int"                      },
    { "getsockname",   "int",    3, "int,ptr,ptr"                  },
    { "getpeername",   "int",    3, "int,ptr,ptr"                  },
    { "htons",         "uint",   1, "uint"                         },
    { "htonl",         "uint",   1, "uint"                         },
    { "ntohs",         "uint",   1, "uint"                         },
    { "ntohl",         "uint",   1, "uint"                         },
    { "inet_addr",     "uint",   1, "char*"                        },
    { "inet_ntoa",     "char*",  1, "uint"                         },
    { "getaddrinfo",   "int",    4, "char*,char*,ptr,ptr"          },
    { "freeaddrinfo",  "void",   1, "ptr"                          },
    // --- signals ---
    { "signal",        "ptr",    2, "int,ptr"                      },
    { "sigaction",     "int",    3, "int,ptr,ptr"                  },
    { "raise",         "int",    1, "int"                          },
    { "kill",          "int",    2, "int,int"                      },
    // --- setjmp / longjmp ---
    { "setjmp",        "int",    1, "ptr"                          },
    { "longjmp",       "void",   2, "ptr,int"                      },
    { "sigsetjmp",     "int",    2, "ptr,int"                      },
    { "siglongjmp",    "void",   2, "ptr,int"                      },
    // --- ioctl / pipe ---
    { "ioctl",         "int",    3, "int,ulong,ptr"                },
    { "pipe",          "int",    1, "ptr"                          },
    { "pipe2",         "int",    2, "ptr,int"                      },
    { "dup",           "int",    1, "int"                          },
    { "dup2",          "int",    2, "int,int"                      },
    { "fcntl",         "int",    3, "int,int,int"                  },
    { "select",        "int",    5, "int,ptr,ptr,ptr,ptr"          },
    { "poll",          "int",    3, "ptr,uint,int"                 },
    { "epoll_create",  "int",    1, "int"                          },
    { "epoll_create1", "int",    1, "int"                          },
    { "epoll_ctl",     "int",    4, "int,int,int,ptr"              },
    { "epoll_wait",    "int",    4, "int,ptr,int,int"              },
    // --- math (float variants) ---
    { "sinf",          "float",  1, "float"                        },
    { "cosf",          "float",  1, "float"                        },
    { "tanf",          "float",  1, "float"                        },
    { "asinf",         "float",  1, "float"                        },
    { "acosf",         "float",  1, "float"                        },
    { "atanf",         "float",  1, "float"                        },
    { "atan2f",        "float",  2, "float,float"                  },
    { "sqrtf",         "float",  1, "float"                        },
    { "powf",          "float",  2, "float,float"                  },
    { "floorf",        "float",  1, "float"                        },
    { "ceilf",         "float",  1, "float"                        },
    { "roundf",        "float",  1, "float"                        },
    { "truncf",        "float",  1, "float"                        },
    { "fabsf",         "float",  1, "float"                        },
    { "expf",          "float",  1, "float"                        },
    { "exp2f",         "float",  1, "float"                        },
    { "logf",          "float",  1, "float"                        },
    { "log2f",         "float",  1, "float"                        },
    { "log10f",        "float",  1, "float"                        },
    { "fmodf",         "float",  2, "float,float"                  },
    { "fminf",         "float",  2, "float,float"                  },
    { "fmaxf",         "float",  2, "float,float"                  },
    { "hypotf",        "float",  2, "float,float"                  },
    { "ldexpf",        "float",  2, "float,int"                    },
    { "frexpf",        "float",  2, "float,ptr"                    },
    { "modff",         "float",  2, "float,ptr"                    },
    // --- math (double extras) ---
    { "atan",          "double", 1, "double"                       },
    { "atan2",         "double", 2, "double,double"                },
    { "asin",          "double", 1, "double"                       },
    { "acos",          "double", 1, "double"                       },
    { "tan",           "double", 1, "double"                       },
    { "exp",           "double", 1, "double"                       },
    { "exp2",          "double", 1, "double"                       },
    { "round",         "double", 1, "double"                       },
    { "trunc",         "double", 1, "double"                       },
    { "fmin",          "double", 2, "double,double"                },
    { "fmax",          "double", 2, "double,double"                },
    { "fmod",          "double", 2, "double,double"                },
    { "hypot",         "double", 2, "double,double"                },
    { "ldexp",         "double", 2, "double,int"                   },
    { "frexp",         "double", 2, "double,ptr"                   },
    { "modf",          "double", 2, "double,ptr"                   },
    { "cbrt",          "double", 1, "double"                       },
    { "cbrtf",         "float",  1, "float"                        },
    { "logb",          "double", 1, "double"                       },
    { "logbf",         "float",  1, "float"                        },
    // --- pthread extras ---
    { "pthread_cond_init",      "int",  2, "ptr,ptr"               },
    { "pthread_cond_destroy",   "int",  1, "ptr"                   },
    { "pthread_cond_wait",      "int",  2, "ptr,ptr"               },
    { "pthread_cond_signal",    "int",  1, "ptr"                   },
    { "pthread_cond_broadcast", "int",  1, "ptr"                   },
    { "pthread_cond_timedwait", "int",  3, "ptr,ptr,ptr"           },
    { "pthread_rwlock_init",    "int",  2, "ptr,ptr"               },
    { "pthread_rwlock_destroy", "int",  1, "ptr"                   },
    { "pthread_rwlock_rdlock",  "int",  1, "ptr"                   },
    { "pthread_rwlock_wrlock",  "int",  1, "ptr"                   },
    { "pthread_rwlock_unlock",  "int",  1, "ptr"                   },
    { "pthread_rwlock_tryrdlock","int", 1, "ptr"                   },
    { "pthread_rwlock_trywrlock","int", 1, "ptr"                   },
    { "pthread_key_create",     "int",  2, "ptr,ptr"               },
    { "pthread_key_delete",     "int",  1, "ulong"                 },
    { "pthread_getspecific",    "void*",1, "ulong"                 },
    { "pthread_setspecific",    "int",  2, "ulong,void*"           },
    { "pthread_once",           "int",  2, "ptr,ptr"               },
    { "pthread_self",           "ulong",0, ""                      },
    { "pthread_detach",         "int",  1, "ulong"                 },
    { "pthread_exit",           "void", 1, "void*"                 },
    { "pthread_cancel",         "int",  1, "ulong"                 },
    { "pthread_attr_init",      "int",  1, "ptr"                   },
    { "pthread_attr_destroy",   "int",  1, "ptr"                   },
    { "pthread_attr_setstacksize","int",2, "ptr,size_t"            },
    { "pthread_attr_getstacksize","int",2, "ptr,ptr"               },
    { "pthread_attr_setdetachstate","int",2,"ptr,int"              },
    { "pthread_mutex_trylock",  "int",  1, "ptr"                   },
    { "pthread_mutex_timedlock","int",  2, "ptr,ptr"               },
    // --- semaphore ---
    { "sem_init",      "int",    3, "ptr,int,uint"                 },
    { "sem_wait",      "int",    1, "ptr"                          },
    { "sem_trywait",   "int",    1, "ptr"                          },
    { "sem_timedwait", "int",    2, "ptr,ptr"                      },
    { "sem_post",      "int",    1, "ptr"                          },
    { "sem_destroy",   "int",    1, "ptr"                          },
    // --- C++ runtime extras ---
    { "__cxa_pure_virtual",     "void", 0, ""                      }, // pure virtual call guard
    { "__cxa_atexit",           "int",  3, "ptr,void*,void*"       }, // register destructor
    { "__cxa_finalize",         "void", 1, "void*"                 }, // run atexit handlers
    { "__cxa_rethrow",          "void", 0, ""                      }, // rethrow current exception
    { "__cxa_demangle",         "char*",4, "char*,char*,ptr,ptr"   }, // demangle symbol
    { "__cxa_current_exception_type","ptr",0,""                    }, // get current exception type
    { "__gxx_personality_v0",   "int",  5, "int,int,long,ptr,ptr"  }, // Itanium EH personality
    { "_Unwind_Resume",         "void", 1, "ptr"                   }, // resume stack unwinding
    { "_Unwind_RaiseException", "int",  1, "ptr"                   }, // initiate unwinding
    { "__stack_chk_fail",       "void", 0, ""                      }, // stack smash detected
    { "__stack_chk_guard",      "ptr",  0, ""                      }, // stack canary value
    { "_ZSt9terminatev",        "void", 0, ""                      }, // std::terminate()
    { "_ZSt17__throw_bad_allocv","void",0, ""                      }, // std::__throw_bad_alloc()
    { "_ZSt20__throw_length_errorPKc","void",1,"char*"             }, // __throw_length_error
    { "_ZSt24__throw_out_of_rangePKc","void",1,"char*"             }, // __throw_out_of_range
    { "_ZSt21__throw_runtime_errorPKc","void",1,"char*"            }, // __throw_runtime_error
    { "_ZSt20__throw_logic_errorPKc","void",1,"char*"              }, // __throw_logic_error
    { "_ZSt19__throw_range_errorPKc","void",1,"char*"              }, // __throw_range_error
    // operator new / delete extended variants
    { "_ZnwmRKSt9nothrow_t",    "void*",2, "size_t,ptr"            }, // operator new(nothrow)
    { "_ZnamRKSt9nothrow_t",    "void*",2, "size_t,ptr"            }, // operator new[](nothrow)
    { "_ZdlPvRKSt9nothrow_t",   "void", 2, "void*,ptr"             }, // operator delete(nothrow)
    { "_ZdaPvRKSt9nothrow_t",   "void", 2, "void*,ptr"             }, // operator delete[](nothrow)
    { "_ZdaPv",                 "void", 1, "void*"                  }, // operator delete[](void*)
    { "_ZdaPvm",                "void", 2, "void*,size_t"           }, // operator delete[](void*,size_t)
    // --- STL std::string (libstdc++ / libc++ ABI, AArch64) ---
    // Mangled names for the most common basic_string<char> methods.
    // These show up as func_0x... calls in stripped Unity/NDK binaries.
    { "_ZNSsC1EPKcRKSaIcE",  "void", 2, "ptr,char*"               }, // string(const char*, alloc)
    { "_ZNSsC1EPKc",         "void", 1, "char*"                    }, // string(const char*)
    { "_ZNSsC1ERKS_",        "void", 1, "ptr"                      }, // string(const string&)
    { "_ZNSsC1Ev",           "void", 0, ""                         }, // string()
    { "_ZNSsD1Ev",           "void", 0, ""                         }, // ~string()
    { "_ZNSsD2Ev",           "void", 0, ""                         }, // ~string() base
    { "_ZNSsaSERKSs",        "ptr",  1, "ptr"                      }, // operator=(const string&)
    { "_ZNSsaSEPKc",         "ptr",  1, "char*"                    }, // operator=(const char*)
    { "_ZNSs6appendEPKc",    "ptr",  1, "char*"                    }, // append(const char*)
    { "_ZNSs6appendERKSs",   "ptr",  1, "ptr"                      }, // append(const string&)
    { "_ZNSs6appendEPKcm",   "ptr",  2, "char*,size_t"             }, // append(const char*, n)
    { "_ZNSs6appendEmc",     "ptr",  2, "size_t,int"               }, // append(n, char)
    { "_ZNSs6assignEPKc",    "ptr",  1, "char*"                    }, // assign(const char*)
    { "_ZNSs6assignERKSs",   "ptr",  1, "ptr"                      }, // assign(const string&)
    { "_ZNSs6assignEPKcm",   "ptr",  2, "char*,size_t"             }, // assign(const char*, n)
    { "_ZNSs4findEcm",       "size_t", 2, "int,size_t"             }, // find(char, pos)
    { "_ZNSs4findEPKcm",     "size_t", 2, "char*,size_t"           }, // find(const char*, pos)
    { "_ZNSs5rfindEcm",      "size_t", 2, "int,size_t"             }, // rfind(char, pos)
    { "_ZNSs5rfindEPKcm",    "size_t", 2, "char*,size_t"           }, // rfind(const char*, pos)
    { "_ZNSs6substrEmm",     "ptr",  2, "size_t,size_t"            }, // substr(pos, len)
    { "_ZNSs5eraseEmm",      "ptr",  2, "size_t,size_t"            }, // erase(pos, len)
    { "_ZNSs6insertEmPKc",   "ptr",  2, "size_t,char*"             }, // insert(pos, s)
    { "_ZNSs7replaceEmmPKc", "ptr",  3, "size_t,size_t,char*"      }, // replace
    { "_ZNSs5clearEv",       "void", 0, ""                         }, // clear()
    { "_ZNSs7reserveEm",     "void", 1, "size_t"                   }, // reserve(n)
    { "_ZNSs6resizeEmc",     "void", 2, "size_t,int"               }, // resize(n,c)
    { "_ZNSs9push_backEc",   "void", 1, "int"                      }, // push_back(char)
    { "_ZNSs8pop_backEv",    "void", 0, ""                         }, // pop_back()
    { "_ZNKSs4sizeEv",       "size_t", 0, ""                       }, // size()
    { "_ZNKSs6lengthEv",     "size_t", 0, ""                       }, // length()
    { "_ZNKSs5emptyEv",      "bool", 0, ""                         }, // empty()
    { "_ZNKSs8capacityEv",   "size_t", 0, ""                       }, // capacity()
    { "_ZNKSs5c_strEv",      "char*", 0, ""                        }, // c_str()
    { "_ZNKSs4dataEv",       "char*", 0, ""                        }, // data()
    { "_ZNKSseqERKSs",       "bool", 1, "ptr"                      }, // operator==(const string&)
    { "_ZNKSsltERKSs",       "bool", 1, "ptr"                      }, // operator<
    { "_ZNKSs7compareERKSs", "int",  1, "ptr"                      }, // compare(const string&)
    { "_ZNKSs7compareEPKc",  "int",  1, "char*"                    }, // compare(const char*)
    { "_ZStplIcSt11char_traitsIcESaIcEENSt7__cxx1112basic_stringIT_T0_T1_EERKS8_PKS5_",
                             "ptr",  2, "ptr,char*"                 }, // operator+(string, const char*)
    // libstdc++ __cxx11 ABI (GCC 5+, NDK 22 gcc mode)
    { "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEC1EPKc",
                             "void", 1, "char*"                     }, // string(const char*)
    { "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev",
                             "void", 0, ""                          }, // ~string()
    { "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE6appendEPKc",
                             "ptr",  1, "char*"                     }, // append(const char*)
    { "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE9push_backEc",
                             "void", 1, "int"                       }, // push_back(char)
    { "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE4sizeEv",
                             "size_t", 0, ""                        }, // size()
    { "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5c_strEv",
                             "char*", 0, ""                         }, // c_str()
    { "_ZNKSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5emptyEv",
                             "bool", 0, ""                          }, // empty()
    // libc++ variants (clang NDK r23+) — extended
    { "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1EPKc",
                             "void", 1, "char*"                     }, // string(const char*)
    { "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1ERKS5_",
                             "void", 1, "ptr"                       }, // string(const string&)
    { "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1Ev",
                             "void", 0, ""                          }, // string()
    { "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev",
                             "void", 0, ""                          }, // ~string()
    { "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEaSERKS5_",
                             "ptr",  1, "ptr"                       }, // operator=(const string&)
    { "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEaSEPKc",
                             "ptr",  1, "char*"                     }, // operator=(const char*)
    { "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKc",
                             "ptr",  1, "char*"                     }, // append(const char*)
    { "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendERKS5_",
                             "ptr",  1, "ptr"                       }, // append(const string&)
    { "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKcm",
                             "ptr",  2, "char*,size_t"              }, // append(const char*,n)
    { "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6assignEPKc",
                             "ptr",  1, "char*"                     }, // assign(const char*)
    { "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6assignERKS5_",
                             "ptr",  1, "ptr"                       }, // assign(const string&)
    { "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE9push_backEc",
                             "void", 1, "int"                       }, // push_back(char)
    { "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5clearEv",
                             "void", 0, ""                          }, // clear()
    { "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7reserveEm",
                             "void", 1, "size_t"                    }, // reserve(n)
    { "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6resizeEmc",
                             "void", 2, "size_t,int"                }, // resize(n,c)
    { "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6insertEmPKc",
                             "ptr",  2, "size_t,char*"              }, // insert(pos,s)
    { "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5eraseEmm",
                             "ptr",  2, "size_t,size_t"             }, // erase(pos,len)
    { "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6substrEmm",
                             "ptr",  2, "size_t,size_t"             }, // substr(pos,len)
    { "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4sizeEv",
                             "size_t", 0, ""                        }, // size()
    { "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6lengthEv",
                             "size_t", 0, ""                        }, // length()
    { "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5emptyEv",
                             "bool", 0, ""                          }, // empty()
    { "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE8capacityEv",
                             "size_t", 0, ""                        }, // capacity()
    { "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5c_strEv",
                             "char*", 0, ""                         }, // c_str()
    { "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4dataEv",
                             "char*", 0, ""                         }, // data()
    { "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4findEcm",
                             "size_t", 2, "int,size_t"              }, // find(char,pos)
    { "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4findEPKcm",
                             "size_t", 2, "char*,size_t"            }, // find(const char*,pos)
    { "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5rfindEcm",
                             "size_t", 2, "int,size_t"              }, // rfind(char,pos)
    { "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7compareEPKc",
                             "int",  1, "char*"                     }, // compare(const char*)
    { "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7compareERKS5_",
                             "int",  1, "ptr"                       }, // compare(const string&)
    // libc++ std::string_view
    { "_ZNKSt3__117basic_string_viewIcNS_11char_traitsIcEEE4sizeEv",
                             "size_t", 0, ""                        }, // string_view::size()
    { "_ZNKSt3__117basic_string_viewIcNS_11char_traitsIcEEE4dataEv",
                             "char*", 0, ""                         }, // string_view::data()
    { "_ZNKSt3__117basic_string_viewIcNS_11char_traitsIcEEE5emptyEv",
                             "bool", 0, ""                          }, // string_view::empty()
    // --- STL std::vector (common operations) ---
    { "_ZNSt6vectorIiSaIiEEpbERKi",  "void", 1, "ptr"              }, // push_back(int)
    { "_ZNSt6vectorIfSaIfEEpbERKf",  "void", 1, "float"            }, // push_back(float)
    { "_ZNKSt6vectorIiSaIiEE4sizeEv","size_t", 0, ""               }, // size()
    { "_ZNKSt6vectorIiSaIiEE5emptyEv","bool", 0, ""                }, // empty()
    { "_ZNSt6vectorIiSaIiEE5clearEv", "void", 0, ""                }, // clear()
    { "_ZNSt6vectorIiSaIiEE6resizeEm","void", 1, "size_t"          }, // resize(n)
    { "_ZNSt6vectorIiSaIiEE7reserveEm","void",1, "size_t"          }, // reserve(n)
    // libc++ std::vector<uint8_t>
    { "_ZNSt3__16vectorIhNS_9allocatorIhEEE9push_backERKh",
                             "void", 1, "ptr"                       }, // push_back(uint8_t)
    { "_ZNSt3__16vectorIhNS_9allocatorIhEEE6resizeEm",
                             "void", 1, "size_t"                    }, // resize(n)
    { "_ZNSt3__16vectorIhNS_9allocatorIhEEE7reserveEm",
                             "void", 1, "size_t"                    }, // reserve(n)
    { "_ZNKSt3__16vectorIhNS_9allocatorIhEEE4sizeEv",
                             "size_t", 0, ""                        }, // size()
    { "_ZNSt3__16vectorIiNS_9allocatorIiEEE9push_backERKi",
                             "void", 1, "ptr"                       }, // vector<int>::push_back
    { "_ZNSt3__16vectorIfNS_9allocatorIfEEE9push_backERKf",
                             "void", 1, "ptr"                       }, // vector<float>::push_back
    { "_ZNSt3__16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEE9push_backERKS6_",
                             "void", 1, "ptr"                       }, // vector<string>::push_back
    // --- STL std::shared_ptr / unique_ptr ---
    { "_ZNSt3__118make_shared_internalIPNS_6threadEJRS1_EEENSt3__16vectorINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS4_IS6_EEEENS_13__make_sharedIT_EERKT0_",
                             "ptr",  1, "ptr"                       }, // ignore: too specific
    { "__shared_ptr_emplace", "ptr",  2, "ptr,size_t"               }, // shared_ptr internals
    // --- STL std::unordered_map / std::map ---
    { "_ZNSt3__113unordered_mapINSt7__cxx1112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEiNS_4hashIS7_EENS_8equal_toIS7_EENS4_INS_4pairIKS7_iEEEEED1Ev",
                             "void", 0, ""                          }, // ~unordered_map
    // --- STL allocator / new/delete internals ---
    { "_ZnwmSt11align_val_t","void*", 2, "size_t,size_t"           }, // operator new(size_t, align_val_t)
    { "_ZdlPvSt11align_val_t","void", 2, "void*,size_t"            }, // operator delete(void*, align_val_t)
    { "_ZdlPvmSt11align_val_t","void",3, "void*,size_t,size_t"     }, // operator delete(void*, size_t, align_val_t)
    // --- std::mutex / std::recursive_mutex ---
    { "_ZNSt3__15mutexC1Ev",     "void", 0, ""                     }, // mutex()
    { "_ZNSt3__15mutexD1Ev",     "void", 0, ""                     }, // ~mutex()
    { "_ZNSt3__15mutex4lockEv",  "void", 0, ""                     }, // mutex::lock()
    { "_ZNSt3__15mutex6unlockEv","void", 0, ""                      }, // mutex::unlock()
    { "_ZNSt3__15mutex8try_lockEv","bool",0,""                      }, // mutex::try_lock()
    { "_ZNSt3__116recursive_mutexC1Ev",  "void",0,""               }, // recursive_mutex()
    { "_ZNSt3__116recursive_mutexD1Ev",  "void",0,""               }, // ~recursive_mutex()
    { "_ZNSt3__116recursive_mutex4lockEv","void",0,""              }, // recursive_mutex::lock()
    { "_ZNSt3__116recursive_mutex6unlockEv","void",0,""            }, // recursive_mutex::unlock()
    // --- std::thread ---
    { "_ZNSt3__16threadD1Ev",    "void", 0, ""                     }, // ~thread()
    { "_ZNSt3__16thread4joinEv", "void", 0, ""                     }, // thread::join()
    { "_ZNSt3__16thread6detachEv","void",0, ""                     }, // thread::detach()
    { "_ZNKSt3__16thread15get_native_handleEv","ulong",0,""        }, // get_native_handle()
    // --- std::exception ---
    { "_ZNSt13exception_ptrD1Ev","void", 0, ""                     }, // ~exception_ptr()
    { "_ZNSt13runtime_errorC1EPKc","void",1,"char*"                }, // runtime_error(const char*)
    { "_ZNKSt13runtime_error4whatEv","char*",0,""                  }, // runtime_error::what()
    { "_ZNSt12logic_errorC1EPKc","void", 1, "char*"                }, // logic_error(const char*)
    { "_ZNKSt12logic_error4whatEv","char*",0,""                    }, // logic_error::what()
    // --- Android NDK extras ---
    { "__android_log_vprint",    "int",  3, "int,char*,ptr"         },
    { "__android_log_assert",    "void", 3, "char*,char*,char*"     },
    { "AAsset_getLength",        "long", 1, "ptr"                   },
    { "AAsset_getLength64",      "long", 1, "ptr"                   },
    { "AAsset_seek",             "long", 3, "ptr,long,int"          },
    { "AAsset_seek64",           "long", 3, "ptr,long,int"          },
    { "AAsset_getBuffer",        "ptr",  1, "ptr"                   },
    { "AAsset_getRemainingLength","long",1, "ptr"                   },
    { "AAssetManager_open",      "ptr",  3, "ptr,char*,int"         },
    { "AAssetManager_openDir",   "ptr",  2, "ptr,char*"             },
    { "AAssetDir_getNextFileName","char*",1,"ptr"                   },
    { "AAssetDir_close",         "void", 1, "ptr"                   },
    { "ALooper_prepare",         "ptr",  1, "int"                   },
    { "ALooper_acquire",         "void", 1, "ptr"                   },
    { "ALooper_release",         "void", 1, "ptr"                   },
    { "ALooper_pollOnce",        "int",  4, "int,ptr,ptr,ptr"       },
    { "ALooper_pollAll",         "int",  4, "int,ptr,ptr,ptr"       },
    { "ALooper_addFd",           "int",  5, "ptr,int,int,int,ptr,ptr"},
    { "ALooper_removeFd",        "int",  2, "ptr,int"               },
    { "ALooper_wake",            "void", 1, "ptr"                   },
    { "ALooper_forThread",       "ptr",  0, ""                      },
    { "ANativeWindow_acquire",   "void", 1, "ptr"                   },
    { "ANativeWindow_release",   "void", 1, "ptr"                   },
    { "ANativeWindow_getWidth",  "int",  1, "ptr"                   },
    { "ANativeWindow_getHeight", "int",  1, "ptr"                   },
    { "ANativeWindow_getFormat", "int",  1, "ptr"                   },
    { "ANativeWindow_setBuffersGeometry","int",4,"ptr,int,int,int"  },
    { "ANativeWindow_lock",      "int",  3, "ptr,ptr,ptr"           },
    { "ANativeWindow_unlockAndPost","int",1,"ptr"                   },
    { "ANativeWindow_fromSurface","ptr", 2, "ptr,ptr"               },
    { "AInputEvent_getType",     "int",  1, "ptr"                   },
    { "AMotionEvent_getAction",  "int",  1, "ptr"                   },
    { "AMotionEvent_getX",       "float",2,"ptr,size_t"             },
    { "AMotionEvent_getY",       "float",2,"ptr,size_t"             },
    { "AMotionEvent_getPointerCount","size_t",1,"ptr"               },
    { "AKeyEvent_getKeyCode",    "int",  1, "ptr"                   },
    { "AKeyEvent_getAction",     "int",  1, "ptr"                   },
    // --- il2cpp codegen helpers (Unity AArch64) ---
    // These appear in virtually every il2cpp-compiled Unity game as
    // func_0x... calls from managed method implementations.
    { "il2cpp_codegen_initialize_runtime_metadata",
                             "void", 1, "ptr"                       },
    { "il2cpp_codegen_initialize_method_metadata",
                             "void", 1, "ptr"                       },
    { "il2cpp_codegen_raise_exception",
                             "void", 1, "ptr"                       },
    { "il2cpp_codegen_raise_null_reference_exception",
                             "void", 0, ""                          },
    { "il2cpp_codegen_raise_index_out_of_range_exception",
                             "void", 0, ""                          },
    { "il2cpp_codegen_class_from_type",
                             "ptr",  1, "ptr"                       },
    { "il2cpp_codegen_object_new",
                             "ptr",  1, "ptr"                       },
    { "il2cpp_codegen_array_new_specific",
                             "ptr",  2, "ptr,int"                   },
    { "il2cpp_codegen_array_new",
                             "ptr",  2, "ptr,int"                   },
    { "il2cpp_array_new_specific",
                             "ptr",  2, "ptr,int"                   },
    { "il2cpp_array_length",  "int", 1, "ptr"                       },
    { "il2cpp_codegen_string_new_from_char_array",
                             "ptr",  2, "ptr,int"                   },
    { "il2cpp_string_new",    "ptr",  1, "char*"                    },
    { "il2cpp_string_new_len","ptr",  2, "char*,uint"               },
    { "il2cpp_codegen_string_new_wrapper",
                             "ptr",  1, "char*"                     },
    { "il2cpp_value_box",     "ptr",  2, "ptr,ptr"                  },
    { "il2cpp_object_unbox",  "ptr",  1, "ptr"                      },
    { "il2cpp_runtime_invoke","ptr",  4, "ptr,ptr,ptr,ptr"          },
    { "il2cpp_runtime_invoke_convert_args",
                             "ptr",  5, "ptr,ptr,ptr,int,ptr"       },
    { "il2cpp_runtime_class_init",
                             "void", 1, "ptr"                       },
    { "IL2CPP_RUNTIME_CLASS_INIT",
                             "void", 1, "ptr"                       },
    { "il2cpp_gc_alloc_fixed", "ptr", 1, "size_t"                   },
    { "il2cpp_gc_free_fixed",  "void",1, "ptr"                      },
    { "il2cpp_gc_collect",     "void",1, "int"                      },
    { "il2cpp_monitor_enter",  "void",1, "ptr"                      },
    { "il2cpp_monitor_exit",   "void",1, "ptr"                      },
    { "il2cpp_monitor_try_enter","bool",2, "ptr,uint"               },
    { "il2cpp_monitor_pulse",  "void",1, "ptr"                      },
    { "il2cpp_monitor_pulse_all","void",1,"ptr"                     },
    { "il2cpp_monitor_wait",   "void",1, "ptr"                      },
    { "il2cpp_type_get_object","ptr",  1, "ptr"                     },
    { "il2cpp_method_get_name","char*",1, "ptr"                     },
    { "il2cpp_class_get_name", "char*",1, "ptr"                     },
    { "il2cpp_class_get_namespace","char*",1,"ptr"                  },
    { "il2cpp_class_get_parent","ptr",1, "ptr"                      },
    { "il2cpp_class_is_assignable_from","bool",2,"ptr,ptr"          },
    { "il2cpp_class_from_name","ptr",  3, "ptr,char*,char*"         },
    { "il2cpp_domain_get",     "ptr",  0, ""                        },
    { "il2cpp_domain_get_assemblies","ptr",2,"ptr,ptr"              },
    { "il2cpp_assembly_get_image","ptr",1,"ptr"                     },
    { "il2cpp_image_get_class","ptr",  2, "ptr,uint"                },
    { "il2cpp_field_get_value","void", 3, "ptr,ptr,ptr"             },
    { "il2cpp_field_set_value","void", 3, "ptr,ptr,ptr"             },
    { "il2cpp_field_static_get_value","void",2,"ptr,ptr"            },
    { "il2cpp_field_static_set_value","void",2,"ptr,ptr"            },
    { "il2cpp_property_get_get_method","ptr",1,"ptr"                },
    { "il2cpp_object_get_class","ptr", 1, "ptr"                     },
    { "il2cpp_object_get_virtual_method","ptr",2,"ptr,ptr"          },
    { "il2cpp_object_is_inst", "ptr",  2, "ptr,ptr"                 },
    { "il2cpp_resolve_icall",  "ptr",  1, "char*"                   },
    { "il2cpp_add_internal_call","void",2,"char*,ptr"               },
    { "il2cpp_thread_attach",  "ptr",  1, "ptr"                     },
    { "il2cpp_thread_detach",  "void", 1, "ptr"                     },
    { "il2cpp_thread_current", "ptr",  0, ""                        },
    // il2cpp codegen cast / type check helpers
    { "IsInstClass",           "ptr",  2, "ptr,ptr"                 },
    { "IsInstSealed",          "ptr",  2, "ptr,ptr"                 },
    { "IsInstInterface",       "ptr",  2, "ptr,ptr"                 },
    { "CastclassClass",        "ptr",  2, "ptr,ptr"                 },
    { "CastclassSealed",       "ptr",  2, "ptr,ptr"                 },
    { "CastclassInterface",    "ptr",  2, "ptr,ptr"                 },
    { "il2cpp_codegen_is_assignable_from","bool",2,"ptr,ptr"        },
    // il2cpp exception helpers
    { "il2cpp_codegen_get_message_of_null_reference_exception",
                             "ptr",  0, ""                          },
    { "il2cpp_codegen_get_argument_exception",
                             "ptr",  2, "char*,char*"               },
    { "il2cpp_codegen_get_argument_null_exception",
                             "ptr",  1, "char*"                     },
    { "il2cpp_codegen_get_invalid_operation_exception",
                             "ptr",  1, "char*"                     },
    { "il2cpp_codegen_get_overflow_exception",
                             "ptr",  0, ""                          },
    { "il2cpp_codegen_get_not_supported_exception",
                             "ptr",  1, "char*"                     },
    { "il2cpp_codegen_get_format_exception",
                             "ptr",  1, "char*"                     },
    // il2cpp boxing helpers for value types
    { "Box",                   "ptr",  2, "ptr,ptr"                 },
    { "UnBox",                 "ptr",  1, "ptr"                     },
    { "UnBox_Any",             "ptr",  2, "ptr,ptr"                 },
    { "Castclass",             "ptr",  2, "ptr,ptr"                 },
    { "IsInst",                "ptr",  2, "ptr,ptr"                 },
    // --- Unity engine NDK helpers (libunity.so exports) ---
    { "UnitySendMessage",      "void", 3, "char*,char*,char*"       },
    { "UnityGetGLContext",     "ptr",  0, ""                        },
};
static const size_t kStdlibProtoCount =
    sizeof(kStdlibProtos) / sizeof(kStdlibProtos[0]);

// ---------------------------------------------------------------------------
// il2cpp method name pattern detection
//
// il2cpp-compiled managed methods are named:
//   ClassName_MethodName_m<decimal-id>
// e.g. Player_TakeDamage_m1234567, NetworkManager_Update_m987654
//
// Returns true if `name` matches this pattern, and extracts a human-readable
// display name (e.g. "Player::TakeDamage") into `out_display`.
// ---------------------------------------------------------------------------
static bool is_il2cpp_method(const std::string& name, std::string* out_display = nullptr) {
    if (name.size() < 5) return false;
    size_t underscore_m = std::string::npos;
    size_t pos = name.size();
    while (pos > 0) {
        --pos;
        if (!std::isdigit((unsigned char)name[pos])) {
            if (pos >= 1 && name[pos] == 'm' && name[pos - 1] == '_') {
                size_t digits_start = pos + 1;
                if (digits_start < name.size() &&
                    std::isdigit((unsigned char)name[digits_start])) {
                    underscore_m = pos - 1;
                }
            }
            break;
        }
    }
    if (underscore_m == std::string::npos || underscore_m == 0) return false;

    if (out_display) {
        std::string base = name.substr(0, underscore_m);
        size_t last_sep = base.rfind('_');
        if (last_sep != std::string::npos && last_sep > 0) {
            *out_display = base.substr(0, last_sep) + "::" + base.substr(last_sep + 1);
        } else {
            *out_display = base;
        }
    }
    return true;
}

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
                                const ElfParseResult& elf,
                                const std::map<uint64_t, std::string>& func_map)
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

    // --- Source 3: PLT-style local-export thunks (e.g. "j_is_odd") ---
    //
    // Phase 3.5/4.5 in run_analysis() rename PLT stub addresses that target
    // a function *within this same binary* (as opposed to an external
    // libc import) to "j_<real_name>" — these addresses never exist in
    // elf.functions or elf.symbols, since they were synthesized purely from
    // GOT-relocation analysis, not from a real ELF symbol table entry. A
    // direct call from one local function to another that happens to route
    // through such a stub (common when a function is also dynamically
    // exported) would otherwise have NO entry at all in the signature
    // cache for that call's target address, leaving the call completely
    // unresolved at decompile time — it gets neither a name nor a type,
    // and (combined with the dead-code-elimination issue fixed previously)
    // can end up dropping the call and its result entirely.
    //
    // Register each such thunk address under the REAL function's name
    // (stripping the "j_" prefix) and copy over any signature already
    // known for that real function (symbol-derived or stdlib), so a call
    // through the thunk is typed exactly as if it called the real function
    // directly.
    for (const auto& [addr, name] : func_map) {
        if (sigmap.count(addr)) continue;  // already has a real symbol entry
        if (name.size() <= 2 || name[0] != 'j' || name[1] != '_') continue;

        std::string real_name = name.substr(2);
        // Find the real function's own signature, if we already have one,
        // by name (the real function's own address is a separate sigmap
        // entry from Source 1/2 — look it up by matching name rather than
        // address, since we don't have its address handy here without an
        // extra reverse lookup).
        const FuncSignature* real_sig = nullptr;
        for (const auto& [a, s] : sigmap) {
            if (s.name == real_name) { real_sig = &s; break; }
        }

        FuncSignature s;
        s.address = addr;
        s.name    = real_name;          // resolve the call to the real name,
                                         // not the synthetic "j_" thunk name
        if (real_sig) {
            s.return_type = real_sig->return_type;
            s.param_count = real_sig->param_count;
            s.params_csv  = real_sig->params_csv;
            s.source      = real_sig->source;
        } else {
            s.source = "symbol";
        }
        sigmap[addr] = std::move(s);
    }

    // --- Source 4: apply stdlib/il2cpp prototypes where name matches ---
    for (auto& [addr, sig] : sigmap) {
        // Strip thunk prefix for lookup ("j_malloc" → "malloc").
        std::string lookup_name = sig.name;
        if (lookup_name.size() > 2 &&
            lookup_name[0] == 'j' && lookup_name[1] == '_')
            lookup_name = lookup_name.substr(2);

        // 4a. Stdlib / il2cpp named-function table match.
        auto it = g_stdlib_map.find(lookup_name);
        if (it != g_stdlib_map.end()) {
            const StdlibProto* p = it->second;
            sig.return_type = p->return_type ? p->return_type : "";
            sig.param_count = p->param_count;
            sig.params_csv  = p->params_csv ? p->params_csv : "";
            // Tag il2cpp named helpers differently from libc/C++ runtime.
            bool is_il2cpp_helper =
                lookup_name.rfind("il2cpp_", 0) == 0 ||
                lookup_name.rfind("IL2CPP_", 0) == 0 ||
                lookup_name == "IsInstClass"      || lookup_name == "IsInstSealed"  ||
                lookup_name == "IsInstInterface"  || lookup_name == "CastclassClass"||
                lookup_name == "CastclassSealed"  || lookup_name == "CastclassInterface" ||
                lookup_name == "Box"   || lookup_name == "UnBox" ||
                lookup_name == "UnBox_Any" || lookup_name == "Castclass" ||
                lookup_name == "IsInst" || lookup_name == "UnitySendMessage";
            sig.source = is_il2cpp_helper ? "il2cpp" : "stdlib";
            continue;
        }

        // 4b. il2cpp generated managed-method pattern: ClassName_Method_m<id>.
        // These aren't in the static table (there are millions of possible
        // names), but we can recognise the pattern and apply a generic
        // il2cpp managed-method prototype: ptr return, first param is
        // the "this" pointer (or null for static), last param is
        // Il2CppMethodInfo* (always ptr). param_count=-1 (unknown argc)
        // is the honest answer since we don't know the C# signature,
        // but we set source="il2cpp" so the decompiler at least names
        // the call site correctly and trusts the return value.
        if (sig.source != "il2cpp" && is_il2cpp_method(lookup_name)) {
            sig.return_type = "ptr";
            sig.param_count = -1;
            sig.params_csv  = "";
            sig.source      = "il2cpp";
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
            // This path re-parses the ELF from scratch with no access to a
            // freshly-computed func_map (that only exists inside
            // run_analysis()). Reconstruct an equivalent map from the
            // function list already persisted to the DB during the
            // original analysis — it already contains the correctly
            // thunk-renamed entries (e.g. "j_is_odd") that Source 3 in
            // populate_sig_cache() needs.
            std::map<uint64_t, std::string> func_map_from_db;
            for (const auto& f : ctx.db->get_functions(ctx.binary_id)) {
                func_map_from_db[(uint64_t)f.address] = f.name;
            }
            populate_sig_cache(ctx, elf, func_map_from_db);
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
    populate_sig_cache(ctx, elf, func_map);

    return true;
}

// resolve_ghidra_tokens removed: ELF symbols are now injected directly into
// Ghidra's scope in Stage 2.5b of decompiler_bridge, so the decompiler
// emits real names without any text-rewriting pass.

#if 0  // DEAD CODE — kept for reference only; never compiled
static std::string resolve_ghidra_tokens_DELETED(const std::string& code,
                                                   const ElfParseResult& elf) {
    if (code.empty()) return code;

    // Build a VA → name lookup (symbols first, then functions without override).
    std::unordered_map<uint64_t, std::string> sym_map;
    for (const auto& sym : elf.symbols) {
        if (sym.address == 0 || sym.name.empty()) continue;
        sym_map.emplace(sym.address, sym.name);
    }
    for (const auto& fn : elf.functions) {
        if (fn.address == 0 || fn.name.empty()) continue;
        sym_map.emplace(fn.address, fn.name);   // won't overwrite if sym already present
    }

    // Token descriptor: which prefix to scan for, and how to resolve it.
    struct TokenDef {
        const char* prefix;
        size_t      plen;
        bool        is_data;    // true → try C-string; false → function lookup
        bool        drop_inner; // true → inner FUN_ within PTR_FUN_ already handled
    };

    // Order matters: longer prefixes must come before shorter ones that share a prefix.
    static const TokenDef kTokens[] = {
        {"thunk_FUN_", 10, false, false},
        {"PTR_FUN_",    8, false, true },   // skip the inner FUN_ hex — handled here
        {"FUN_",        4, false, false},
        {"DAT_",        4, true,  false},
        {"LAB_",        4, false, false},
        {"EXTR_",       5, false, false},
        // Ghidra's lowercase variant: func_0x<hex> — emitted for stripped
        // Unity/NDK binaries and some Ghidra analysis configurations.
        // Prefix length 7 = strlen("func_0x"). Hex digits follow immediately.
        {"func_0x",     7, false, false},
        // Ghidra emits unk_<hex> directly for unresolved data symbols (not
        // through DAT_→unk_ fallback). Treat as data: try C-string, then
        // sym_map, then keep the existing unk_<hex> as-is.
        {"unk_",        4, true,  false},
    };
    static const size_t kTokenCount = sizeof(kTokens) / sizeof(kTokens[0]);

    std::string out;
    out.reserve(code.size() + 64);
    size_t pos = 0;

    while (pos < code.size()) {
        // Find the earliest matching token.
        size_t earliest    = std::string::npos;
        size_t e_plen      = 0;
        bool   e_is_data   = false;

        for (size_t ti = 0; ti < kTokenCount; ++ti) {
            size_t f = code.find(kTokens[ti].prefix, pos);
            if (f < earliest) {
                earliest  = f;
                e_plen    = kTokens[ti].plen;
                e_is_data = kTokens[ti].is_data;
            }
        }

        if (earliest == std::string::npos) {
            out.append(code, pos, std::string::npos);
            break;
        }

        // Word-boundary check: must not be immediately preceded by [A-Za-z0-9_].
        if (earliest > 0 &&
            (std::isalnum((unsigned char)code[earliest - 1]) ||
             code[earliest - 1] == '_')) {
            out.append(code, pos, earliest - pos + 1);
            pos = earliest + 1;
            continue;
        }

        // Consume hex digits after the prefix.
        size_t p          = earliest + e_plen;
        size_t hex_start  = p;
        while (p < code.size() && std::isxdigit((unsigned char)code[p])) ++p;
        size_t hex_len    = p - hex_start;

        // Must be 4..16 hex digits, not immediately followed by an identifier char.
        if (hex_len < 4 || hex_len > 16 ||
            (p < code.size() &&
             (std::isalnum((unsigned char)code[p]) || code[p] == '_'))) {
            out.append(code, pos, earliest - pos + 1);
            pos = earliest + 1;
            continue;
        }

        // For PTR_FUN_ there may be a second _YYYYYYYY chunk (vtable variant).
        // Consume and discard it — we only need the first VA.
        if (p < code.size() && code[p] == '_') {
            size_t p2 = p + 1;
            size_t h2 = p2;
            while (p2 < code.size() && std::isxdigit((unsigned char)code[p2])) ++p2;
            if (p2 - h2 >= 4 && p2 - h2 <= 16 &&
                (p2 >= code.size() ||
                 (!std::isalnum((unsigned char)code[p2]) && code[p2] != '_'))) {
                p = p2;  // skip the second address chunk
            }
        }

        uint64_t va = std::strtoull(std::string(code, hex_start, hex_len).c_str(),
                                    nullptr, 16);

        out.append(code, pos, earliest - pos);  // emit everything before the token

        if (e_is_data) {
            // DAT_: try C-string, then symbol name, then unk_ADDR.
            std::string s = elf_read_cstring(elf, va);
            if (!s.empty()) {
                out += '"'; out += escape_for_literal(s); out += '"';
            } else {
                auto it = sym_map.find(va);
                if (it != sym_map.end()) {
                    out += it->second;
                } else {
                    char buf[32];
                    snprintf(buf, sizeof(buf), "unk_%llx", (unsigned long long)va);
                    out += buf;
                }
            }
        } else {
            // FUN_ / PTR_FUN_ / LAB_ / EXTR_: look up real name, else sub_ADDR.
            auto it = sym_map.find(va);
            if (it != sym_map.end()) {
                out += it->second;
            } else {
                // Emit IDA-style sub_ADDR (uppercase hex, no leading zeros).
                char buf[32];
                snprintf(buf, sizeof(buf), "sub_%llX", (unsigned long long)va);
                out += buf;
            }
        }
        pos = p;
    }
    return out;
}
#endif  // end DEAD CODE block

// ---------------------------------------------------------------------------
// JNI implementations
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
        ctx->last_error = "function id " + std::to_string((long long)func_id) +
                          " not found in DB (binary_id=" +
                          std::to_string((long long)ctx->binary_id) + ")";
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
        ctx->last_error = "ELF re-parse failed: " + elf.error +
                          " (path=" + ctx->file_path + ")";
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
        // Build a diagnostic: list all executable sections so the caller
        // can see whether the function address falls in any of them.
        std::ostringstream va_err;
        va_err << "va_to_ptr: function " << fn.name
               << " addr=0x" << std::hex << fn.address
               << " size=" << std::dec << code_len
               << " not in any executable section (";
        bool first = true;
        for (const auto& sec : elf.sections) {
            if (!sec.is_executable()) continue;
            if (!first) va_err << ", ";
            va_err << "0x" << std::hex << sec.address
                   << "+0x" << sec.size;
            first = false;
        }
        if (first) va_err << "NO EXECUTABLE SECTIONS";
        va_err << ") fn.size=" << std::dec << fn.size;
        ctx->last_error = va_err.str();
        return env->NewStringUTF("");
    }

    // Build the flat C-struct array of typed function signatures.
    // Strings are owned by sig_cache and remain valid for the duration of this
    // call.  ELF symbol labelling is now handled on-demand inside PeekScope.
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

    // ------------------------------------------------------------------
    // Guard the decompile call against SIGSEGV from Ghidra's internals.
    // ------------------------------------------------------------------
    struct sigaction guard_sa, old_sa_segv, old_sa_bus;
    memset(&guard_sa, 0, sizeof(guard_sa));
    guard_sa.sa_sigaction = decomp_segv_guard;
    guard_sa.sa_flags     = SA_SIGINFO;
    sigemptyset(&guard_sa.sa_mask);
    sigaction(SIGSEGV, &guard_sa, &old_sa_segv);
    sigaction(SIGBUS,  &guard_sa, &old_sa_bus);

    PeekInferredSig inferred = {};
    char* result_cstr = nullptr;
    bool decomp_crashed = false;

    g_decomp_active = true;
    if (sigsetjmp(g_decomp_jmp, /*savemask=*/1) == 0) {
        result_cstr = peek_decompile_elf(
            elf,
            fn.name.c_str(),
            (uint64_t)fn.address,
            (uint64_t)code_len,
            c_sigs.empty() ? nullptr : c_sigs.data(), c_sigs.size(),
            &inferred);
        g_decomp_active = false;
    } else {
        // Recovered from SIGSEGV/SIGBUS inside Ghidra — g_decomp_active
        // already cleared by the guard handler before siglongjmp.
        decomp_crashed = true;
        LOGE("Decompiler SIGSEGV recovered for %s — skipping pseudocode",
             fn.name.c_str());
    }

    // Restore the original handlers (crash_handler.cpp) unconditionally.
    sigaction(SIGSEGV, &old_sa_segv, nullptr);
    sigaction(SIGBUS,  &old_sa_bus,  nullptr);

    if (decomp_crashed) {
        ctx->last_error = std::string("decompiler fault (SIGSEGV) on ") + fn.name;
        return env->NewStringUTF(
            "// Pseudocode unavailable: decompiler fault on this function.\n"
            "// The function may contain instructions not supported by the\n"
            "// decompiler (e.g. ARMv8.1 LSE atomics or unusual encodings).\n");
    }

    if (!result_cstr) {
        const char* bridge_err = peek_decompile_get_last_error();
        LOGE("Decompile returned null for %s — %s", fn.name.c_str(), bridge_err);
        ctx->last_error = bridge_err ? bridge_err : "decompile bridge returned null";
        return env->NewStringUTF("");
    }

    std::string result(result_cstr);
    free(result_cstr);

    // 0. (resolve_ghidra_tokens removed — ELF symbols were injected into
    //    Ghidra's scope in Stage 2.5b, so the decompiler emits real names.)

    // 1. JNI-aware signature, param renames, vtable call resolution, and
    //    JNI constant naming.  Also normalises Ghidra internal type names
    //    (xunknown1/2/4/8 → uint8_t/…, in_x0 → param1, CONCAT/CARRY/…).
    //    No-op for non-JNI functions except the normalisation passes.
    result = jni_annotate(fn.name, result);

    // 2. ELF data-reference resolution: annotate any remaining xRam<addr>
    //    tokens (addresses with no ELF symbol) with the string they point
    //    to, and annotate known JNI string arguments.
    result = resolve_data_refs(result, elf);

    // 3. Algorithm detection: prepend "// detected - NAME (detection may be
    //    wrong)" comment lines for recognised crypto/obfuscation patterns.
    result = annotate_algorithms(result);

    // 4. Store with a version tag so stale cache entries are auto-detected.
    ctx->db->store_pseudocode((int64_t)func_id, CACHE_TAG + result);
    LOGI("Decompiled %s (%zu chars)", fn.name.c_str(), result.size());

    // 5. Lazy learning — if the decompiler inferred a prototype for this
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

// ============================================================
// IL2CPP / Unity binary JNI entry points
// ============================================================

// Read an entire file into a vector<uint8_t>. Returns empty vector on failure.
static std::vector<uint8_t> read_file_bytes(const std::string& path) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return {};
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return {}; }
    std::vector<uint8_t> buf((size_t)sz);
    size_t got = fread(buf.data(), 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) return {};
    return buf;
}

extern "C" {

// -------------------------------------------------------
// nativeOpenUnityBinary
// -------------------------------------------------------
// Runs the standard analysis pipeline on the il2cpp.so,
// then parses global-metadata.dat and applies IL2CPP names
// to all matched functions.
// Returns a handle (same type as nativeOpenBinary) or 0.
JNIEXPORT jlong JNICALL
Java_com_nex_peek_PeekNative_nativeOpenUnityBinary(
    JNIEnv* env, jobject,
    jstring j_so_path,
    jstring j_meta_path,
    jstring j_db_dir)
{
    std::string so_path   = jstr(env, j_so_path);
    std::string meta_path = jstr(env, j_meta_path);
    std::string db_dir    = jstr(env, j_db_dir);

    auto* ctx = new AnalysisContext();
    ctx->is_unity  = true;
    ctx->file_path = so_path;
    ctx->tmp_dir   = db_dir;

    // --- DB setup (mirrors nativeOpenBinary logic) ---
    std::string hash = sha256_file(so_path);
    ctx->file_hash = hash;

    std::string db_path = db_dir + "/peek_cache.db";
    ctx->db = std::make_unique<AnalysisDb>(db_path);
    if (!ctx->db->open()) {
        ctx->last_error = "DB open failed: " + ctx->db->last_error();
        LOGE("Unity: %s", ctx->last_error.c_str());
        return reinterpret_cast<jlong>(ctx);
    }

    // Check cache first
    int64_t cached_id = ctx->db->find_binary(hash);
    if (cached_id >= 0) {
        ctx->binary_id = cached_id;
        LOGI("Unity: loaded from cache binary_id=%lld", (long long)cached_id);
        // Re-apply IL2CPP names even from cache (metadata may have changed)
    } else {
        if (!run_analysis(*ctx)) {
            LOGE("Unity: run_analysis failed: %s", ctx->last_error.c_str());
            return reinterpret_cast<jlong>(ctx);
        }
    }

    // --- Read files for IL2CPP dump ---
    std::vector<uint8_t> so_buf   = read_file_bytes(so_path);
    std::vector<uint8_t> meta_buf = read_file_bytes(meta_path);

    if (so_buf.empty()) {
        ctx->il2cpp_log = "ERROR: failed to read il2cpp.so\n";
        LOGE("Unity: failed to read so");
        return reinterpret_cast<jlong>(ctx);
    }
    if (meta_buf.empty()) {
        ctx->il2cpp_log = "ERROR: failed to read global-metadata.dat\n";
        LOGE("Unity: failed to read metadata");
        return reinterpret_cast<jlong>(ctx);
    }

    LOGI("Unity: running il2cpp_dump (so=%zu bytes, meta=%zu bytes)",
         so_buf.size(), meta_buf.size());

    Il2CppDumpResult dump = il2cpp_dump(
        so_buf.data(),   so_buf.size(),
        meta_buf.data(), meta_buf.size());

    ctx->il2cpp_log  = dump.log;
    ctx->il2cpp_log += dump.success ? "" : ("\nERROR: " + dump.error);

    if (!dump.success) {
        LOGE("Unity: il2cpp_dump failed: %s", dump.error.c_str());
        return reinterpret_cast<jlong>(ctx);
    }

    LOGI("Unity: il2cpp_dump returned %zu symbols", dump.methods.size());

    // --- Apply names ---
    // 1. Build addr→name map
    std::unordered_map<uint64_t, std::string> name_map;
    std::vector<FuncSignature>                sigs;
    name_map.reserve(dump.methods.size());
    sigs.reserve(dump.methods.size());

    for (auto& sym : dump.methods) {
        name_map[sym.address] = sym.name;

        FuncSignature sig;
        sig.address = sym.address;
        sig.name    = sym.name;
        sig.source  = "il2cpp";
        sigs.push_back(sig);
    }

    // 2. Rename functions table entries
    ctx->db->update_function_names_bulk(ctx->binary_id, name_map, /*overwrite=*/false);

    // 3. Store as signatures (for decompiler name resolution)
    ctx->db->store_signatures(ctx->binary_id, sigs);

    ctx->il2cpp_log += "\nApplied " + std::to_string(dump.methods.size()) + " IL2CPP names.\n";
    LOGI("Unity: applied %zu names", dump.methods.size());

    return reinterpret_cast<jlong>(ctx);
}

// Returns the IL2CPP dump diagnostic log for the given handle.
JNIEXPORT jstring JNICALL
Java_com_nex_peek_PeekNative_nativeGetIl2CppLog(JNIEnv* env, jobject, jlong handle)
{
    if (handle == 0) return env->NewStringUTF("");
    auto* ctx = reinterpret_cast<AnalysisContext*>(handle);
    return env->NewStringUTF(ctx->il2cpp_log.c_str());
}

// Returns 1 if the binary opened at this handle is a Unity IL2CPP binary.
JNIEXPORT jboolean JNICALL
Java_com_nex_peek_PeekNative_nativeIsUnityBinary(JNIEnv* env, jobject, jlong handle)
{
    if (handle == 0) return JNI_FALSE;
    auto* ctx = reinterpret_cast<AnalysisContext*>(handle);
    return ctx->is_unity ? JNI_TRUE : JNI_FALSE;
}

} // extern "C" (Unity block)

// ============================================================
// nativeListBinaries — returns recent analyses for home screen
// ============================================================
extern "C" {

JNIEXPORT jstring JNICALL
Java_com_nex_peek_PeekNative_nativeListBinaries(JNIEnv* env, jobject, jstring j_db_dir)
{
    const char* raw = env->GetStringUTFChars(j_db_dir, nullptr);
    std::string db_dir(raw ? raw : "");
    env->ReleaseStringUTFChars(j_db_dir, raw);

    AnalysisDb db(db_dir + "/peek_cache.db");
    if (!db.open()) return env->NewStringUTF("");

    auto list = db.list_recent_binaries(20);
    std::string out;
    out.reserve(list.size() * 80);
    for (auto& info : list) {
        out += std::to_string(info.id)             + "\t";
        out += info.file_path                       + "\t";
        out += std::to_string(info.function_count)  + "\t";
        out += std::to_string(info.last_analyzed)   + "\n";
    }
    return env->NewStringUTF(out.c_str());
}

} // extern "C" (listBinaries block)
