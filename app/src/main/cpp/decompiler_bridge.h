#pragma once
#include "elf_parser.h"
#include <stdint.h>

// One-time decompiler init — call from nativeInitDecompiler with the path to
// the directory holding AARCH64.{sla,ldefs,pspec,cspec}.
int peek_decompiler_init(const char* spec_dir);

// ---------------------------------------------------------------------------
// Typed function signature — passed to the decompiler so call sites get
// correctly typed parameters and return values.
// ---------------------------------------------------------------------------
struct PeekFuncSig {
    uint64_t    address;
    const char* name;
    const char* return_type;    // "void","bool","int","uint","long","ulong",
                                // "float","double","ptr","void*","char*",
                                // "size_t","unknown", or NULL
    int         param_count;    // -1 = unknown
    const char* params_csv;     // comma-separated param types, or NULL
};

// Inferred prototype extracted from the decompiler's own analysis.
struct PeekInferredSig {
    char return_type[64];
    char params_csv[512];
    int  param_count;
    int  is_set;   // non-zero on success
};

// ---------------------------------------------------------------------------
// Primary decompile entry point (r2ghidra-style: full ELF + PeekScope).
//
//   elf            — parsed ELF (owns full raw bytes + sections + symbols).
//   func_name      — target function name.
//   real_func_addr — virtual address of the function in the ELF.
//   func_len       — byte length of the function body.
//   sigs / sig_count — typed signatures for callee functions.
//   out_inferred   — filled with the prototype the decompiler inferred.
//
// Returns a malloc'd NUL-terminated C string (caller must free) containing
// the decompiled C text, or nullptr on failure.  On failure,
// peek_decompile_get_last_error() returns a human-readable message.
// ---------------------------------------------------------------------------
char* peek_decompile_elf(
    const ElfParseResult& elf,
    const char*           func_name,
    uint64_t              real_func_addr,
    uint64_t              func_len,
    const PeekFuncSig*    sigs,
    size_t                sig_count,
    PeekInferredSig*      out_inferred
);

// Returns the last error set by peek_decompile_elf on this thread.
// Never returns nullptr — returns "" if no error has been set.
const char* peek_decompile_get_last_error(void);

void peek_decompiler_shutdown(void);
