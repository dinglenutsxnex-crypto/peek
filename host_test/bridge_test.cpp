#include "decompiler_bridge.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

int main(int argc, char** argv) {
    const char* specdir = (argc > 1) ? argv[1] : "./spec";
    int ok = peek_decompiler_init(specdir);
    printf("init ok=%d\n", ok);
    if (!ok) return 1;

    // --- TEST 1: read_cycles — mrs x0, cntvct_el0 ; ret ---
    {
        uint8_t bytes[] = {0x40,0xe0,0x3b,0xd5, 0xc0,0x03,0x5f,0xd6};
        PeekInferredSig inferred = {};
        char* out = peek_decompile_bytes_v2(bytes, sizeof(bytes),
            "read_cycles", "/tmp/bt_read_cycles.bin", 0x9690,
            nullptr, 0, &inferred);
        printf("\n=== read_cycles ===\n");
        if (out) { printf("%s\n", out); free(out); }
        else printf("FAILED: %s\n", peek_decompile_get_last_error());
        printf("inferred.is_set=%d ret=%s params=%s n=%d\n",
               inferred.is_set, inferred.return_type, inferred.params_csv, inferred.param_count);
    }

    // --- TEST 2: exported_void-equivalent — just prologue/epilogue, no body ---
    // stp x29,x30,[sp,#-0x10]! ; mov x29,sp ; ldp x29,x30,[sp],#0x10 ; ret
    {
        uint8_t bytes[] = {
            0xfd,0x7b,0xbf,0xa9,   // stp x29,x30,[sp,#-0x10]!
            0xfd,0x03,0x00,0x91,   // mov x29, sp
            0xfd,0x7b,0xc1,0xa8,   // ldp x29,x30,[sp],#0x10
            0xc0,0x03,0x5f,0xd6,   // ret
        };
        PeekInferredSig inferred = {};
        char* out = peek_decompile_bytes_v2(bytes, sizeof(bytes),
            "exported_void", "/tmp/bt_exported_void.bin", 0x9BCC,
            nullptr, 0, &inferred);
        printf("\n=== exported_void ===\n");
        if (out) { printf("%s\n", out); free(out); }
        else printf("FAILED: %s\n", peek_decompile_get_last_error());
        printf("inferred.is_set=%d ret=%s params=%s n=%d\n",
               inferred.is_set, inferred.return_type, inferred.params_csv, inferred.param_count);
    }

    // --- TEST 3: is_even-style — literal-return branch vs. tail-call-return branch ---
    // cmp x0,#0 ; b.ne L1 ; mov x0,#1 ; ret ; L1: sub x0,x0,#1 ; b is_odd_like (0xA000)
    {
        uint8_t bytes[] = {
            0x1f,0x00,0x00,0xf1,   // cmp x0, #0
            0x61,0x00,0x00,0x54,   // b.ne +12 (to L1)
            0x20,0x00,0x80,0xd2,   // movz x0, #1
            0xc0,0x03,0x5f,0xd6,   // ret
            0x00,0x04,0x00,0xd1,   // L1: sub x0, x0, #1
            0xfb,0x03,0x00,0x14,   // b 0xA000 (is_odd_like) — tail call, no BL/RET
        };
        PeekFuncSig sig = {};
        sig.address = 0xA000;
        sig.name = "is_odd_like";
        sig.return_type = "int";
        sig.param_count = 1;
        sig.params_csv = "int";
        PeekInferredSig inferred = {};
        char* out = peek_decompile_bytes_v2(bytes, sizeof(bytes),
            "is_even_like", "/tmp/bt_is_even.bin", 0x9000,
            &sig, 1, &inferred);
        printf("\n=== is_even_like (with sibling sig for tail-call target) ===\n");
        if (out) { printf("%s\n", out); free(out); }
        else printf("FAILED: %s\n", peek_decompile_get_last_error());
        printf("inferred.is_set=%d ret=%s params=%s n=%d\n",
               inferred.is_set, inferred.return_type, inferred.params_csv, inferred.param_count);
    }

    return 0;
}
