// Ground-truth host-side test: real JNI_OnLoad bytes from lib64.so
// Bytes verified byte-for-byte against attached_assets/lib64_1782387001149.so
// (dynsym: vaddr=0x4610, size=0xC4=196, file_offset=0x4610 in PT_LOAD base=0)
//
// Two runs:
//   RUN A — eaddr = ram->getHighest()   (old behaviour, matches jni_onload_test.cpp)
//   RUN B — eaddr = len - 1             (fix in decompiler_bridge.cpp line 143)
//
// This tells us whether the fix is sufficient at the SLEIGH level,
// independent of Gradle / Android build / JNI / SQLite cache.

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

// Real JNI_OnLoad bytes — byte-for-byte from lib64.so offset 0x4610..0x46D3
// Verified: so_bytes == test_bytes (Python confirms exact match)
static const uint8_t real_bytes[196] = {
    0xFF,0x43,0x01,0xD1, 0xF4,0x4F,0x03,0xA9, 0xFD,0x7B,0x04,0xA9, 0xFD,0x03,0x01,0x91,
    0x53,0xD0,0x3B,0xD5, 0x68,0x16,0x40,0xF9, 0xC2,0x00,0x80,0x52, 0xD4,0x00,0x80,0x52,
    0xE1,0x23,0x00,0x91, 0xA8,0x83,0x1E,0xF8, 0x08,0x00,0x40,0xF9, 0x22,0x00,0xA0,0x72,
    0x34,0x00,0xA0,0x72, 0x08,0x19,0x40,0xF9, 0x00,0x01,0x3F,0xD6, 0x60,0x00,0x00,0x34,
    0x00,0x00,0x80,0x12, 0x17,0x00,0x00,0x14, 0xE0,0x07,0x40,0xF9, 0x01,0x00,0x00,0x90,
    0x21,0x38,0x1C,0x91, 0x08,0x00,0x40,0xF9, 0x08,0x19,0x40,0xF9, 0x00,0x01,0x3F,0xD6,
    0xE1,0x03,0x00,0xAA, 0xE0,0xFE,0xFF,0xB4, 0x88,0x00,0x00,0xD0, 0x08,0xE1,0x24,0x91,
    0x09,0x09,0x40,0xF9, 0x00,0x01,0xC0,0x3D, 0xE0,0x07,0x40,0xF9, 0xE2,0x43,0x00,0x91,
    0xE9,0x13,0x00,0xF9, 0xE0,0x07,0x80,0x3D, 0x08,0x00,0x40,0xF9, 0xE3,0x03,0x00,0x32,
    0x08,0x5D,0x43,0xF9, 0x00,0x01,0x3F,0xD6, 0x1F,0x00,0x00,0x71, 0x80,0x02,0x9F,0x5A,
    0x68,0x16,0x40,0xF9, 0xA9,0x83,0x5E,0xF8, 0x1F,0x01,0x09,0xEB, 0xA1,0x00,0x00,0x54,
    0xFD,0x7B,0x44,0xA9, 0xF4,0x4F,0x43,0xA9, 0xFF,0x43,0x01,0x91, 0xC0,0x03,0x5F,0xD6,
    0x40,0xFF,0xFF,0x97,
};

static bool writeBytes(const char *path, const uint8_t *data, size_t len)
{
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) { std::cerr << "Cannot write " << path << "\n"; return false; }
    f.write(reinterpret_cast<const char *>(data), len);
    return !!f;
}

static std::string runDecompile(const char *binPath, const char *funcName,
                                uintb eaddrVal, const char *specdir)
{
    DocumentStorage store;
    RawBinaryArchitecture *arch = nullptr;
    try {
        arch = new RawBinaryArchitecture(binPath, "AARCH64:LE:64:v8A", &std::cerr);
        arch->init(store);
    } catch (const LowlevelError &e) {
        std::cerr << "[S2:arch_init] " << e.explain << "\n";
        delete arch;
        return "";
    }

    AddrSpace *ram = arch->getDefaultCodeSpace();
    Address funcAddr(ram, 0);

    Funcdata *fd = nullptr;
    try {
        fd = arch->symboltab->getGlobalScope()
                 ->addFunction(funcAddr, funcName)
                 ->getFunction();
        if (!fd) {
            std::cerr << "[S3:addFunction] returned null\n";
            delete arch;
            return "";
        }

        Address baddr(ram, 0);
        Address eaddr(ram, eaddrVal);
        std::cerr << "[S3] followFlow baddr=" << baddr << " eaddr=" << eaddr << "\n";
        fd->followFlow(baddr, eaddr);
        std::cerr << "[S3] followFlow OK\n";
    } catch (const LowlevelError &e) {
        std::cerr << "[S3:followFlow] FAILED: " << e.explain << "\n";
        delete arch;
        return "";
    }

    try {
        arch->allacts.getCurrent()->reset(*fd);
        int4 res = arch->allacts.getCurrent()->perform(*fd);
        std::cerr << "[S4] pipeline res=" << res << "\n";
        if (res < 0) {
            delete arch;
            return "";
        }
    } catch (const LowlevelError &e) {
        std::cerr << "[S4:pipeline] FAILED: " << e.explain << "\n";
        delete arch;
        return "";
    }

    std::ostringstream out;
    try {
        arch->print->setOutputStream(&out);
        arch->print->docFunction(fd);
    } catch (const LowlevelError &e) {
        std::cerr << "[S5:docFunction] FAILED: " << e.explain << "\n";
        delete arch;
        return "";
    }

    delete arch;
    return out.str();
}

int main(int argc, char **argv)
{
    const char *specdir = (argc > 1) ? argv[1] : "./spec";
    const size_t len = sizeof(real_bytes);

    std::vector<std::string> specDirs = { specdir };
    startDecompilerLibrary(specDirs);

    const char *binPath = "/tmp/real_jni_onload.bin";
    if (!writeBytes(binPath, real_bytes, len)) return 1;

    std::cerr << "\n=== RUN A: eaddr = ram->getHighest() (old behaviour) ===\n";
    {
        DocumentStorage store;
        RawBinaryArchitecture *tmpArch =
            new RawBinaryArchitecture(binPath, "AARCH64:LE:64:v8A", &std::cerr);
        tmpArch->init(store);
        uintb highest = tmpArch->getDefaultCodeSpace()->getHighest();
        delete tmpArch;
        std::cerr << "[INFO] highest=" << std::hex << highest << std::dec << "\n";

        std::string outA = runDecompile(binPath, "JNI_OnLoad", highest, specdir);
        std::cout << "\n=== RUN A OUTPUT ===\n";
        if (outA.empty()) std::cout << "(FAILED — see stderr)\n";
        else              std::cout << outA;
        std::cout << "=== END RUN A ===\n";
    }

    std::cerr << "\n=== RUN B: eaddr = len - 1 = 0x"
              << std::hex << (len - 1) << std::dec
              << " (decompiler_bridge.cpp line 143 fix) ===\n";
    {
        std::string outB = runDecompile(binPath, "JNI_OnLoad", (uintb)(len - 1), specdir);
        std::cout << "\n=== RUN B OUTPUT ===\n";
        if (outB.empty()) std::cout << "(FAILED — see stderr)\n";
        else              std::cout << outB;
        std::cout << "=== END RUN B ===\n";
    }

    std::remove(binPath);
    SleighArchitecture::shutdown();
    return 0;
}
