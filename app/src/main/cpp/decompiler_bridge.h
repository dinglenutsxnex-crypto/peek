#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

int   peek_decompiler_init(const char* spec_dir);

/*
 * Decompile `len` bytes of AArch64 code.
 * Returns a malloc'd NUL-terminated C string (caller must free) on success,
 * or nullptr on failure. On failure, peek_decompile_get_last_error() returns
 * a human-readable stage + reason string valid until the next call on this
 * thread.
 */
char* peek_decompile_bytes(const uint8_t* bytes, size_t len,
                            const char* func_name, const char* tmp_path,
                            uint64_t real_func_addr);

/*
 * Returns the last error set by peek_decompile_bytes on this thread.
 * The pointer is valid until the next peek_decompile_bytes call on this thread.
 * Never returns nullptr — returns "" if no error has been set.
 */
const char* peek_decompile_get_last_error(void);

void  peek_decompiler_shutdown(void);

#ifdef __cplusplus
}
#endif
