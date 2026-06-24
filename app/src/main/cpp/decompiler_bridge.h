#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

int   peek_decompiler_init(const char* spec_dir);
char* peek_decompile_bytes(const uint8_t* bytes, size_t len,
                            const char* func_name, const char* tmp_path);
void  peek_decompiler_shutdown(void);

#ifdef __cplusplus
}
#endif
