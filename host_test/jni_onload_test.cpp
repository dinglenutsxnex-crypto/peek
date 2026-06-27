// Targeted debug test for the real JNI_OnLoad function bytes
// Bytes: 0x4610..0x46D3 (196 = 0xC4 bytes, 49 instructions)

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

// Real JNI_OnLoad bytes extracted from the .so listing (0x4610 to 0x46D3)
static const uint8_t jni_onload_real[196] = {
    0xff, 0x43, 0x01, 0xd1,  // [00] 0x000  sub  sp, sp, #0x50
    0xf4, 0x4f, 0x03, 0xa9,  // [01] 0x004  stp  x20, x19, [sp, #0x30]
    0xfd, 0x7b, 0x04, 0xa9,  // [02] 0x008  stp  x29, x30, [sp, #0x40]
    0xfd, 0x03, 0x01, 0x91,  // [03] 0x00C  add  x29, sp, #0x40
    0x53, 0xd0, 0x3b, 0xd5,  // [04] 0x010  mrs  x19, tpidr_el0
    0x68, 0x16, 0x40, 0xf9,  // [05] 0x014  ldr  x8, [x19, #0x28]
    0xc2, 0x00, 0x80, 0x52,  // [06] 0x018  mov  w2, #6
    0xd4, 0x00, 0x80, 0x52,  // [07] 0x01C  mov  w20, #6
    0xe1, 0x23, 0x00, 0x91,  // [08] 0x020  add  x1, sp, #8
    0xa8, 0x83, 0x1e, 0xf8,  // [09] 0x024  stur  x8, [x29, #-0x18]
    0x08, 0x00, 0x40, 0xf9,  // [10] 0x028  ldr  x8, [x0]
    0x22, 0x00, 0xa0, 0x72,  // [11] 0x02C  movk  w2, #1, lsl #16
    0x34, 0x00, 0xa0, 0x72,  // [12] 0x030  movk  w20, #1, lsl #16
    0x08, 0x19, 0x40, 0xf9,  // [13] 0x034  ldr  x8, [x8, #0x30]
    0x00, 0x01, 0x3f, 0xd6,  // [14] 0x038  blr  x8
    0x60, 0x00, 0x00, 0x34,  // [15] 0x03C  cbz  w0, #0x4658 → 0x048
    0x00, 0x00, 0x80, 0x12,  // [16] 0x040  mov  w0, #-1
    0x17, 0x00, 0x00, 0x14,  // [17] 0x044  b    #0x46b0    → 0x0A0
    0xe0, 0x07, 0x40, 0xf9,  // [18] 0x048  ldr  x0, [sp, #8]
    0x01, 0x00, 0x00, 0x90,  // [19] 0x04C  adrp x1, #0x4000 (page-rel → 0 at VA 0)
    0x21, 0x38, 0x1c, 0x91,  // [20] 0x050  add  x1, x1, #0x70e
    0x08, 0x00, 0x40, 0xf9,  // [21] 0x054  ldr  x8, [x0]
    0x08, 0x19, 0x40, 0xf9,  // [22] 0x058  ldr  x8, [x8, #0x30]
    0x00, 0x01, 0x3f, 0xd6,  // [23] 0x05C  blr  x8
    0xe1, 0x03, 0x00, 0xaa,  // [24] 0x060  mov  x1, x0
    0xe0, 0xfe, 0xff, 0xb4,  // [25] 0x064  cbz  x0, #0x4650 → 0x040
    0x88, 0x00, 0x00, 0xd0,  // [26] 0x068  adrp x8, #0x16000 (page-rel → 0x12000 at VA 0)
    0x08, 0xe1, 0x24, 0x91,  // [27] 0x06C  add  x8, x8, #0x938
    0x09, 0x09, 0x40, 0xf9,  // [28] 0x070  ldr  x9, [x8, #0x10]
    0x00, 0x01, 0xc0, 0x3d,  // [29] 0x074  ldr  q0, [x8]
    0xe0, 0x07, 0x40, 0xf9,  // [30] 0x078  ldr  x0, [sp, #8]
    0xe2, 0x43, 0x00, 0x91,  // [31] 0x07C  add  x2, sp, #0x10
    0xe9, 0x13, 0x00, 0xf9,  // [32] 0x080  str  x9, [sp, #0x20]
    0xe0, 0x07, 0x80, 0x3d,  // [33] 0x084  str  q0, [sp, #0x10]
    0x08, 0x00, 0x40, 0xf9,  // [34] 0x088  ldr  x8, [x0]
    0xe3, 0x03, 0x00, 0x32,  // [35] 0x08C  mov  w3, #1
    0x08, 0x5d, 0x43, 0xf9,  // [36] 0x090  ldr  x8, [x8, #0x6b8]
    0x00, 0x01, 0x3f, 0xd6,  // [37] 0x094  blr  x8
    0x1f, 0x00, 0x00, 0x71,  // [38] 0x098  cmp  w0, #0
    0x80, 0x02, 0x9f, 0x5a,  // [39] 0x09C  csinv  w0, w20, wzr, eq
    0x68, 0x16, 0x40, 0xf9,  // [40] 0x0A0  ldr  x8, [x19, #0x28]
    0xa9, 0x83, 0x5e, 0xf8,  // [41] 0x0A4  ldur  x9, [x29, #-0x18]
    0x1f, 0x01, 0x09, 0xeb,  // [42] 0x0A8  cmp  x8, x9
    0xa1, 0x00, 0x00, 0x54,  // [43] 0x0AC  b.ne #0x46d0   → 0x0C0
    0xfd, 0x7b, 0x44, 0xa9,  // [44] 0x0B0  ldp  x29, x30, [sp, #0x40]
    0xf4, 0x4f, 0x43, 0xa9,  // [45] 0x0B4  ldp  x20, x19, [sp, #0x30]
    0xff, 0x43, 0x01, 0x91,  // [46] 0x0B8  add  sp, sp, #0x50
    0xc0, 0x03, 0x5f, 0xd6,  // [47] 0x0BC  ret
    0x40, 0xff, 0xff, 0x97,  // [48] 0x0C0  bl   #0x43d0   → -0x240 at VA 0!
};

// Stage-instrumented decompile: logs each phase to stderr, returns pseudocode or "".
static std::string decompileInstrumented(const uint8_t *bytes, size_t len,
                                          const char *funcName, const char *tmpPath)
{
    std::ofstream f(tmpPath, std::ios::binary | std::ios::trunc);
    if (!f) { std::cerr << "[BRIDGE] Cannot write tmp file " << tmpPath << "\n"; return ""; }
    f.write(reinterpret_cast<const char *>(bytes), len);
    f.close();
    std::cerr << "[STAGE 0] Wrote " << len << " bytes to " << tmpPath << "\n";

    DocumentStorage store;
    RawBinaryArchitecture *arch = nullptr;
    try {
        arch = new RawBinaryArchitecture(tmpPath, "AARCH64:LE:64:v8A", &std::cerr);
        std::cerr << "[STAGE 1] RawBinaryArchitecture constructed\n";
        arch->init(store);
        std::cerr << "[STAGE 2] arch->init complete\n";
    } catch (const LowlevelError &e) {
        std::cerr << "[STAGE 1-2 FATAL] LowlevelError: " << e.explain << "\n";
        delete arch;
        std::remove(tmpPath);
        return "";
    }

    AddrSpace *ram = arch->getDefaultCodeSpace();
    Address funcAddr(ram, 0);
    std::cerr << "[STAGE 3] funcAddr=" << funcAddr << "\n";

    Funcdata *fd = nullptr;
    try {
        fd = arch->symboltab->getGlobalScope()
                 ->addFunction(funcAddr, funcName)
                 ->getFunction();
        std::cerr << "[STAGE 3] addFunction OK, fd=" << (void*)fd << "\n";
    } catch (const LowlevelError &e) {
        std::cerr << "[STAGE 3 FATAL] addFunction LowlevelError: " << e.explain << "\n";
        delete arch;
        std::remove(tmpPath);
        return "";
    }
    if (!fd) {
        std::cerr << "[STAGE 3 FATAL] addFunction returned null Funcdata\n";
        delete arch;
        std::remove(tmpPath);
        return "";
    }

    try {
        Address baddr(ram, 0);
        Address eaddr(ram, ram->getHighest());
        std::cerr << "[STAGE 4] followFlow baddr=" << baddr << " eaddr=" << eaddr << "\n";
        fd->followFlow(baddr, eaddr);
        std::cerr << "[STAGE 4] followFlow complete\n";
    } catch (const LowlevelError &e) {
        std::cerr << "[STAGE 4 FATAL] followFlow LowlevelError: " << e.explain << "\n";
        delete arch;
        std::remove(tmpPath);
        return "";
    } catch (const BadDataError &e) {
        std::cerr << "[STAGE 4 FATAL] followFlow BadDataError: " << e.explain << "\n";
        delete arch;
        std::remove(tmpPath);
        return "";
    }

    try {
        arch->allacts.getCurrent()->reset(*fd);
        std::cerr << "[STAGE 5] reset complete\n";
        int4 res = arch->allacts.getCurrent()->perform(*fd);
        std::cerr << "[STAGE 5] perform complete, res=" << res << "\n";
        if (res < 0) {
            std::cerr << "[STAGE 5 FAIL] pipeline returned res=" << res << "\n";
            arch->allacts.getCurrent()->printState(std::cerr);
            std::cerr << "\n";
            delete arch;
            std::remove(tmpPath);
            return "";
        }
    } catch (const LowlevelError &e) {
        std::cerr << "[STAGE 5 FATAL] perform LowlevelError: " << e.explain << "\n";
        delete arch;
        std::remove(tmpPath);
        return "";
    }

    std::ostringstream out;
    try {
        arch->print->setOutputStream(&out);
        arch->print->docFunction(fd);
        std::cerr << "[STAGE 6] docFunction complete\n";
    } catch (const LowlevelError &e) {
        std::cerr << "[STAGE 6 FATAL] docFunction LowlevelError: " << e.explain << "\n";
        delete arch;
        std::remove(tmpPath);
        return "";
    }

    delete arch;
    std::remove(tmpPath);
    return out.str();
}

int main(int argc, char **argv)
{
    const char *specdir = (argc > 1) ? argv[1] : "./spec";
    std::vector<std::string> specDirs = { specdir };
    startDecompilerLibrary(specDirs);
    std::cerr << "[MAIN] startDecompilerLibrary done\n";

    std::cerr << "\n=== REAL JNI_OnLoad (196 bytes, 0x4610-0x46D3) ===\n";
    std::string out = decompileInstrumented(
        jni_onload_real, sizeof(jni_onload_real),
        "JNI_OnLoad", "/tmp/jni_real.bin");

    std::cout << "\n=== PSEUDOCODE OUTPUT ===\n";
    if (out.empty()) {
        std::cout << "(empty — see stderr for failure stage)\n";
    } else {
        std::cout << out;
    }
    std::cout << "=== END ===\n";

    SleighArchitecture::shutdown();
    return 0;
}
