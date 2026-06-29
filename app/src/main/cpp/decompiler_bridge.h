#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

int   peek_decompiler_init(const char* spec_dir);

/*
 * Lightweight function signature record — plain C so it crosses the
 * decompiler_bridge ABI boundary safely (no C++ types).
 *
 * address     : function virtual address in the original binary.
 * name        : function name (non-null, NUL-terminated).
 * return_type : simplified type string (may be NULL or ""):
 *               void / bool / int / uint / long / ulong / float / double /
 *               ptr  / void* / char* / size_t / unknown
 * param_count : number of parameters, or -1 if unknown.
 * params_csv  : comma-separated param type strings in the same simplified
 *               vocabulary, or NULL/"" if unknown.
 */
typedef struct PeekFuncSig {
    uint64_t    address;
    const char* name;
    const char* return_type;
    int         param_count;
    const char* params_csv;
} PeekFuncSig;

/*
 * Inferred prototype extracted from the decompiler's own analysis.
 * Filled by peek_decompile_bytes_v2 when is_set != 0.
 * Strings use the same simplified vocabulary as PeekFuncSig.
 */
typedef struct PeekInferredSig {
    char return_type[64];
    char params_csv[512];
    int  param_count;
    int  is_set;   /* non-zero on success */
} PeekInferredSig;

/*
 * Lightweight data / code-label record passed to v3.
 *
 * All ELF symbols (both STT_FUNC and STT_OBJECT) are injected into
 * Ghidra's global scope before followFlow so the decompiler emits real
 * names instead of auto-generating FUN_addr / DAT_addr tokens.
 *
 * address : virtual address in the original binary.
 * name    : symbol name (non-null, NUL-terminated).
 * is_func : 1 = function symbol (Scope::addFunction),
 *           0 = data / code label (Scope::addCodeLabel).
 */
typedef struct PeekDataSym {
    uint64_t    address;
    const char* name;
    int         is_func;
} PeekDataSym;

/*
 * V1 — kept for compatibility; calls V3 with zero signatures and no
 * inferred-sig output.  New code should call peek_decompile_bytes_v3.
 *
 * Returns a malloc'd NUL-terminated C string (caller must free) on
 * success, or nullptr on failure.  On failure,
 * peek_decompile_get_last_error() returns a human-readable message valid
 * until the next call on this thread.
 */
char* peek_decompile_bytes(const uint8_t* bytes, size_t len,
                            const char* func_name, const char* tmp_path,
                            uint64_t real_func_addr);

/*
 * V2 — kept for ABI compatibility; calls V3 with zero data syms.
 */
char* peek_decompile_bytes_v2(const uint8_t* bytes, size_t len,
                               const char*    func_name,
                               const char*    tmp_path,
                               uint64_t       real_func_addr,
                               const PeekFuncSig* sigs,
                               size_t         sig_count,
                               PeekInferredSig*   out_inferred);

/*
 * V3 — full implementation.
 *   sigs / sig_count   — typed function signatures for call-site typing.
 *   dsyms / dsym_count — all ELF symbols (functions + data) injected into
 *                        the scope as labels so Ghidra resolves names
 *                        directly instead of emitting FUN_/DAT_ tokens.
 *   out_inferred       — filled with the prototype the decompiler inferred.
 */
char* peek_decompile_bytes_v3(const uint8_t*     bytes,
                               size_t             len,
                               const char*        func_name,
                               const char*        tmp_path,
                               uint64_t           real_func_addr,
                               const PeekFuncSig* sigs,
                               size_t             sig_count,
                               const PeekDataSym* dsyms,
                               size_t             dsym_count,
                               PeekInferredSig*   out_inferred);

/*
 * Returns the last error set by peek_decompile_bytes / v2 on this thread.
 * Never returns nullptr — returns "" if no error has been set.
 */
const char* peek_decompile_get_last_error(void);

void  peek_decompiler_shutdown(void);

#ifdef __cplusplus
}
#endif
