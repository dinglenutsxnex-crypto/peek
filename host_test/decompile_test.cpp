// host-side decompiler pipeline test
// Test 1: 16-byte PLT thunk (already proven)
// Test 2: 49-instruction JNI_OnLoad-like function with real control flow:
//   sub sp / stp prologue, mrs+ldr TLS access, 3× blr indirect calls,
//   2× cbz conditional branches, ldp epilogue + ret

#include "libdecomp.hh"
#include "raw_arch.hh"

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstdio>

using namespace ghidra;

// ----------------------------------------------------------------
// Run one function through the full pipeline and return pseudocode.
// binPath  – raw binary file (bytes starting at virtual offset 0)
// funcName – name to assign the function
// specdir  – directory containing AARCH64.ldefs etc.
// ----------------------------------------------------------------
static std::string decompileFunction(const char *binPath,
                                     const char *funcName,
                                     const char *specdir)
{
    DocumentStorage store;
    RawBinaryArchitecture *arch =
        new RawBinaryArchitecture(binPath, "AARCH64:LE:64:v8A", &std::cerr);

    try {
        arch->init(store);
    } catch (const LowlevelError &e) {
        std::cerr << "Architecture init failed: " << e.explain << "\n";
        delete arch;
        return "";
    }

    AddrSpace *ramSpace = arch->getDefaultCodeSpace();
    Address funcAddr(ramSpace, 0);

    Funcdata *fd = arch->symboltab->getGlobalScope()
                       ->addFunction(funcAddr, funcName)
                       ->getFunction();
    if (!fd) {
        std::cerr << "addFunction returned null Funcdata\n";
        delete arch;
        return "";
    }

    try {
        Address baddr(ramSpace, 0);
        Address eaddr(ramSpace, ramSpace->getHighest());
        fd->followFlow(baddr, eaddr);
    } catch (const LowlevelError &e) {
        std::cerr << "followFlow failed: " << e.explain << "\n";
        delete arch;
        return "";
    }

    arch->allacts.getCurrent()->reset(*fd);
    int4 res = arch->allacts.getCurrent()->perform(*fd);
    if (res < 0) {
        std::cerr << "Decompiler pipeline broke mid-way\n";
        arch->allacts.getCurrent()->printState(std::cerr);
        std::cerr << "\n";
        delete arch;
        return "";
    }
    std::cerr << "Decompilation complete (res=" << res << ")\n";

    std::ostringstream out;
    arch->print->setOutputStream(&out);
    arch->print->docFunction(fd);

    delete arch;
    return out.str();
}

// ----------------------------------------------------------------
// Write a byte buffer to a temp file, return false on failure.
// ----------------------------------------------------------------
static bool writeBytes(const char *path, const uint8_t *data, size_t len)
{
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) { std::cerr << "Cannot write " << path << "\n"; return false; }
    f.write(reinterpret_cast<const char *>(data), len);
    return true;
}

// ----------------------------------------------------------------
// TEST 1 — 16-byte PLT thunk
//   adrp x16, ...  / ldr x17,[x16,#0xff8] / add x16,x16,#0xff8 / br x17
// ----------------------------------------------------------------
static const uint8_t plt_bytes[16] = {
    0x90, 0x00, 0x00, 0xf0,
    0x11, 0xee, 0x47, 0xf9,
    0x10, 0x62, 0x3f, 0x91,
    0x20, 0x02, 0x1f, 0xd6
};

// ----------------------------------------------------------------
// TEST 2 — 49-instruction JNI_OnLoad-like function
//
// Hand-encoded ARM64 (all encodings verified against the AArch64
// reference manual via formula):
//
// PROLOGUE (instrs 0-4, off 0x000-0x010):
//   sub  sp, sp, #0x50
//   stp  x29, x30, [sp, #0x40]
//   stp  x22, x21, [sp, #0x30]
//   stp  x20, x19, [sp, #0x20]
//   add  x29, sp,  #0x40
//
// SAVE ARGS + TLS ACCESS (instrs 5-10, off 0x014-0x028):
//   mov  x19, x0              ; save JavaVM*
//   mov  x20, x1              ; save reserved
//   mrs  x8, tpidr_el0        ; thread-local storage
//   ldr  x8, [x8, #0x28]
//   ldr  x21, [x8, #0x00]     ; fn ptr A
//   ldr  x22, [x8, #0x10]     ; fn ptr B
//
// FIRST INDIRECT CALL (instrs 11-13, off 0x02C-0x034):
//   mov  x0, x19
//   ldr  x1, [x20, #0x00]
//   blr  x21
//
// CBZ #1 (instr 14, off 0x038):
//   cbz  x0, error_A          ; → instr 37 (off 0x094), offset = +92
//
// BODY / NOT-NULL PATH (instrs 15-27, off 0x03C-0x06C):
//   ldr  x8,  [x0, #0x00]
//   ldr  x23, [x8, #0x00]
//   mov  x0, x19
//   mov  x1, x20
//   mov  x2, xzr
//   blr  x23                  ; second indirect call
//   mov  x19, x0
//   ldr  x24, [x0, #0x18]
//   ldr  x25, [x24, #0x00]
//   mov  x0, x19
//   mov  x1, x20
//   blr  x25                  ; third indirect call
//   mov  x21, x0
//
// CBZ #2 (instr 28, off 0x070):
//   cbz  x0, error_B          ; → instr 34 (off 0x088), offset = +24
//
// CONTINUE PATH (instrs 29-32, off 0x074-0x080):
//   ldr  x22, [x21, #0x28]
//   mov  x0, x21
//   blr  x22                  ; fourth indirect call
//   mov  x19, x0
//
// B → EPILOGUE (instr 33, off 0x084):   offset = +44
//
// ERROR_B PATH (instrs 34-35, off 0x088-0x08C):
//   mov  x21, xzr
//   mov  x19, xzr
//
// B → EPILOGUE (instr 36, off 0x090):   offset = +32
//
// ERROR_A PATH (instrs 37-42, off 0x094-0x0A8):
//   mov  x19, xzr
//   mov  x21, xzr
//   mov  x22, xzr
//   nop; nop; nop
//
// B → EPILOGUE (instr 43, off 0x0AC):   offset = +4
//
// EPILOGUE (instrs 44-48, off 0x0B0-0x0C0):
//   ldp  x22, x21, [sp, #0x30]
//   ldp  x20, x19, [sp, #0x20]
//   ldp  x29, x30, [sp, #0x40]
//   add  sp, sp, #0x50
//   ret
// ----------------------------------------------------------------
static const uint8_t jni_onload_bytes[196] = {
    0xFF, 0x43, 0x01, 0xD1,  // [00] 0x000  sub  sp, sp, #0x50
    0xFD, 0x7B, 0x04, 0xA9,  // [01] 0x004  stp  x29, x30, [sp, #0x40]
    0xF6, 0x57, 0x03, 0xA9,  // [02] 0x008  stp  x22, x21, [sp, #0x30]
    0xF4, 0x4F, 0x02, 0xA9,  // [03] 0x00C  stp  x20, x19, [sp, #0x20]
    0xFD, 0x03, 0x01, 0x91,  // [04] 0x010  add  x29, sp, #0x40
    0xF3, 0x03, 0x00, 0xAA,  // [05] 0x014  mov  x19, x0
    0xF4, 0x03, 0x01, 0xAA,  // [06] 0x018  mov  x20, x1
    0x48, 0xD0, 0x3B, 0xD5,  // [07] 0x01C  mrs  x8, tpidr_el0
    0x08, 0x15, 0x40, 0xF9,  // [08] 0x020  ldr  x8,  [x8, #0x28]
    0x15, 0x01, 0x40, 0xF9,  // [09] 0x024  ldr  x21, [x8, #0x00]
    0x16, 0x09, 0x40, 0xF9,  // [10] 0x028  ldr  x22, [x8, #0x10]
    0xE0, 0x03, 0x13, 0xAA,  // [11] 0x02C  mov  x0, x19
    0x81, 0x02, 0x40, 0xF9,  // [12] 0x030  ldr  x1, [x20, #0x00]
    0xA0, 0x02, 0x3F, 0xD6,  // [13] 0x034  blr  x21
    0xE0, 0x02, 0x00, 0xB4,  // [14] 0x038  cbz  x0, error_A (+92 → 0x094)
    0x08, 0x00, 0x40, 0xF9,  // [15] 0x03C  ldr  x8, [x0, #0x00]
    0x17, 0x01, 0x40, 0xF9,  // [16] 0x040  ldr  x23, [x8, #0x00]
    0xE0, 0x03, 0x13, 0xAA,  // [17] 0x044  mov  x0, x19
    0xE1, 0x03, 0x14, 0xAA,  // [18] 0x048  mov  x1, x20
    0xE2, 0x03, 0x1F, 0xAA,  // [19] 0x04C  mov  x2, xzr
    0xE0, 0x02, 0x3F, 0xD6,  // [20] 0x050  blr  x23
    0xF3, 0x03, 0x00, 0xAA,  // [21] 0x054  mov  x19, x0
    0x18, 0x0C, 0x40, 0xF9,  // [22] 0x058  ldr  x24, [x0, #0x18]
    0x19, 0x03, 0x40, 0xF9,  // [23] 0x05C  ldr  x25, [x24, #0x00]
    0xE0, 0x03, 0x13, 0xAA,  // [24] 0x060  mov  x0, x19
    0xE1, 0x03, 0x14, 0xAA,  // [25] 0x064  mov  x1, x20
    0x20, 0x03, 0x3F, 0xD6,  // [26] 0x068  blr  x25
    0xF5, 0x03, 0x00, 0xAA,  // [27] 0x06C  mov  x21, x0
    0xC0, 0x00, 0x00, 0xB4,  // [28] 0x070  cbz  x0, error_B (+24 → 0x088)
    0xB6, 0x16, 0x40, 0xF9,  // [29] 0x074  ldr  x22, [x21, #0x28]
    0xE0, 0x03, 0x15, 0xAA,  // [30] 0x078  mov  x0, x21
    0xC0, 0x02, 0x3F, 0xD6,  // [31] 0x07C  blr  x22
    0xF3, 0x03, 0x00, 0xAA,  // [32] 0x080  mov  x19, x0
    0x0B, 0x00, 0x00, 0x14,  // [33] 0x084  b    epilogue (+44 → 0x0B0)
    0xF5, 0x03, 0x1F, 0xAA,  // [34] 0x088  mov  x21, xzr   [error_B]
    0xF3, 0x03, 0x1F, 0xAA,  // [35] 0x08C  mov  x19, xzr
    0x08, 0x00, 0x00, 0x14,  // [36] 0x090  b    epilogue (+32 → 0x0B0)
    0xF3, 0x03, 0x1F, 0xAA,  // [37] 0x094  mov  x19, xzr   [error_A]
    0xF5, 0x03, 0x1F, 0xAA,  // [38] 0x098  mov  x21, xzr
    0xF6, 0x03, 0x1F, 0xAA,  // [39] 0x09C  mov  x22, xzr
    0x1F, 0x20, 0x03, 0xD5,  // [40] 0x0A0  nop
    0x1F, 0x20, 0x03, 0xD5,  // [41] 0x0A4  nop
    0x1F, 0x20, 0x03, 0xD5,  // [42] 0x0A8  nop
    0x01, 0x00, 0x00, 0x14,  // [43] 0x0AC  b    epilogue (+4 → 0x0B0)
    0xF6, 0x57, 0x43, 0xA9,  // [44] 0x0B0  ldp  x22, x21, [sp, #0x30]  [epilogue]
    0xF4, 0x4F, 0x42, 0xA9,  // [45] 0x0B4  ldp  x20, x19, [sp, #0x20]
    0xFD, 0x7B, 0x44, 0xA9,  // [46] 0x0B8  ldp  x29, x30, [sp, #0x40]
    0xFF, 0x43, 0x01, 0x91,  // [47] 0x0BC  add  sp, sp, #0x50
    0xC0, 0x03, 0x5F, 0xD6,  // [48] 0x0C0  ret
};

int main(int argc, char **argv)
{
    const char *specdir = (argc > 1) ? argv[1] : "./spec";

    // Initialise once; both tests share the same SLEIGH cache.
    std::vector<std::string> specDirs = { specdir };
    startDecompilerLibrary(specDirs);

    // ── TEST 1: PLT thunk ──────────────────────────────────────────
    std::cerr << "\n--- TEST 1: PLT thunk ---\n";
    const char *plt_bin = "/tmp/plt_thunk.bin";
    if (!writeBytes(plt_bin, plt_bytes, sizeof(plt_bytes))) return 1;
    std::string plt_out = decompileFunction(plt_bin, "plt_thunk", specdir);
    std::cout << "=== TEST 1: PLT THUNK ===" << std::endl;
    std::cout << plt_out;
    std::cout << "=== END TEST 1 ===" << std::endl;

    // ── TEST 2: JNI_OnLoad-like function ──────────────────────────
    std::cerr << "\n--- TEST 2: JNI_OnLoad-like (49 instrs) ---\n";
    const char *jni_bin = "/tmp/jni_onload.bin";
    if (!writeBytes(jni_bin, jni_onload_bytes, sizeof(jni_onload_bytes))) return 1;
    std::string jni_out = decompileFunction(jni_bin, "JNI_OnLoad", specdir);
    std::cout << "=== TEST 2: JNI_OnLoad ===" << std::endl;
    std::cout << jni_out;
    std::cout << "=== END TEST 2 ===" << std::endl;

    SleighArchitecture::shutdown();
    return 0;
}
