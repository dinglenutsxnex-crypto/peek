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
 * V1 — kept for compatibility; calls V2 with zero signatures and no
 * inferred-sig output.  New code should call peek_decompile_bytes_v2.
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
 * V2 — like V1 but:
 *   sigs / sig_count  — array of known function signatures for every
 *                       other function in the binary.  These are injected
 *                       into the Ghidra Architecture's global scope before
 *                       followFlow, so that call targets receive correct
 *                       names and (when type info is present) correct
 *                       parameter and return types.  May be NULL / 0.
 *   out_inferred      — if non-NULL and decompilation succeeds, filled
 *                       with the prototype the decompiler inferred for the
 *                       target function.  Useful for lazy learning: store
 *                       the result and feed it back for future callers.
 */
char* peek_decompile_bytes_v2(const uint8_t* bytes, size_t len,
                               const char*    func_name,
                               const char*    tmp_path,
                               uint64_t       real_func_addr,
                               const PeekFuncSig* sigs,
                               size_t         sig_count,
                               PeekInferredSig*   out_inferred);

/*
 * Returns the last error set by peek_decompile_bytes / v2 on this thread.
 * Never returns nullptr — returns "" if no error has been set.
 */
const char* peek_decompile_get_last_error(void);

/*
 * TEMPORARY DIAGNOSTIC: returns trace messages collected during the most
 * recent peek_decompile_bytes_v2 call on this thread (inject_sig behavior,
 * call-survival checks before/after the action pipeline). Valid until the
 * next peek_decompile_bytes_v2 call on this thread, same lifetime rule as
 * peek_decompile_get_last_error(). Remove once the root cause is found.
 */
const char* peek_get_diag_trace(void);

void  peek_decompiler_shutdown(void);

#ifdef __cplusplus
}
#endif
