// Minimal end-to-end proof: ARM64 bytes → SLEIGH → p-code → decompiler → pseudocode
// Mirrors exactly the pattern used in Ghidra's interactive CLI (ifacedecomp.cc).

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

int main(int argc, char **argv) {
    const char *specdir = (argc > 1) ? argv[1] : "./spec";
    const char *binpath = "/tmp/plt_thunk.bin";

    // ----------------------------------------------------------------
    // 1. Write the 16-byte PLT thunk to a temp file.
    //    File offset 0 → ram address 0 (adjustvma default = 0).
    //    adrp x16, ...  / ldr x17, [x16,#0xff8] / add x16, x16, #0xff8 / br x17
    // ----------------------------------------------------------------
    const uint8_t plt_bytes[16] = {
        0x90, 0x00, 0x00, 0xf0,
        0x11, 0xee, 0x47, 0xf9,
        0x10, 0x62, 0x3f, 0x91,
        0x20, 0x02, 0x1f, 0xd6
    };
    {
        std::ofstream f(binpath, std::ios::binary | std::ios::trunc);
        if (!f) { std::cerr << "Cannot write " << binpath << "\n"; return 1; }
        f.write(reinterpret_cast<const char *>(plt_bytes), 16);
    }

    // ----------------------------------------------------------------
    // 2. Initialise the decompiler library.
    //    Pass the spec directory so collectSpecFiles() can find AARCH64.ldefs
    //    (and hence resolve AARCH64.sla / AARCH64.pspec / AARCH64.cspec).
    // ----------------------------------------------------------------
    std::vector<std::string> specDirs = { specdir };
    startDecompilerLibrary(specDirs);

    // ----------------------------------------------------------------
    // 3. Create a RawBinaryArchitecture for the temp file.
    //    target = language id from AARCH64.ldefs → "AARCH64:LE:64:v8A"
    // ----------------------------------------------------------------
    DocumentStorage store;
    RawBinaryArchitecture *arch =
        new RawBinaryArchitecture(binpath, "AARCH64:LE:64:v8A", &std::cerr);

    try {
        arch->init(store);
    } catch (const LowlevelError &e) {
        std::cerr << "Architecture init failed: " << e.explain << "\n";
        return 1;
    }

    // ----------------------------------------------------------------
    // 4. Register the function at ram:0x0 and get its Funcdata.
    //    Exact pattern from IfcAddrrangeLoad::execute (ifacedecomp.cc:512):
    //      dcp->fd = scope->addFunction(offset, name)->getFunction();
    // ----------------------------------------------------------------
    AddrSpace *ramSpace = arch->getDefaultCodeSpace();
    Address funcAddr(ramSpace, 0);

    Funcdata *fd = arch->symboltab->getGlobalScope()
                       ->addFunction(funcAddr, "plt_thunk")
                       ->getFunction();
    if (!fd) {
        std::cerr << "addFunction returned null Funcdata\n";
        return 1;
    }

    // ----------------------------------------------------------------
    // 5. Trace control flow from the entry point across the full space.
    //    Exact pattern from IfaceDecompData::followFlow (ifacedecomp.cc:444-447)
    //    when size == 0.
    // ----------------------------------------------------------------
    try {
        Address baddr(ramSpace, 0);
        Address eaddr(ramSpace, ramSpace->getHighest());
        fd->followFlow(baddr, eaddr);
    } catch (const LowlevelError &e) {
        std::cerr << "followFlow failed: " << e.explain << "\n";
        return 1;
    }

    // ----------------------------------------------------------------
    // 6. Run the full decompiler action pipeline.
    //    Exact pattern from IfcDecompile::execute (ifacedecomp.cc:907-908).
    // ----------------------------------------------------------------
    arch->allacts.getCurrent()->reset(*fd);
    int4 res = arch->allacts.getCurrent()->perform(*fd);
    if (res < 0) {
        std::cerr << "Decompiler pipeline broke mid-way\n";
        arch->allacts.getCurrent()->printState(std::cerr);
        std::cerr << "\n";
        return 1;
    }
    std::cerr << "Decompilation complete (res=" << res << ")\n";

    // ----------------------------------------------------------------
    // 7. Pretty-print the result as C pseudocode.
    //    Exact pattern from IfcPrintCFlat::execute (ifacedecomp.cc:929-931).
    // ----------------------------------------------------------------
    std::ostringstream out;
    arch->print->setOutputStream(&out);
    arch->print->docFunction(fd);

    std::cout << "=== PSEUDOCODE ===" << std::endl;
    std::cout << out.str();
    std::cout << "=== END ===" << std::endl;

    delete arch;
    SleighArchitecture::shutdown();
    return 0;
}
