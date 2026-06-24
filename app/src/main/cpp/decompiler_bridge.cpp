#include "decompiler_bridge.h"

#include "decompiler/libdecomp.hh"
#include "decompiler/raw_arch.hh"

#include <android/log.h>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <streambuf>

#define TAG_BRIDGE "PeekDecomp"
#define LOGI_B(...) __android_log_print(ANDROID_LOG_INFO,  TAG_BRIDGE, __VA_ARGS__)
#define LOGE_B(...) __android_log_print(ANDROID_LOG_ERROR, TAG_BRIDGE, __VA_ARGS__)

using namespace ghidra;

namespace {

struct NullBuf : std::streambuf {
    int overflow(int c) override { return c; }
    std::streamsize xsputn(const char*, std::streamsize n) override { return n; }
};
NullBuf  g_null_buf;
std::ostream g_null_stream(&g_null_buf);

std::once_flag g_init_flag;
bool g_init_ok = false;

} // anonymous namespace

extern "C" {

int peek_decompiler_init(const char* spec_dir) {
    std::call_once(g_init_flag, [spec_dir]() {
        try {
            std::vector<std::string> dirs = { spec_dir };
            startDecompilerLibrary(dirs);
            g_init_ok = true;
            LOGI_B("startDecompilerLibrary OK, specDir=%s", spec_dir);
        } catch (const std::exception& e) {
            LOGE_B("startDecompilerLibrary threw: %s", e.what());
        } catch (...) {
            LOGE_B("startDecompilerLibrary threw unknown exception");
        }
    });
    return g_init_ok ? 1 : 0;
}

char* peek_decompile_bytes(const uint8_t* bytes, size_t len,
                            const char* func_name, const char* tmp_path) {
    if (!g_init_ok || !bytes || len == 0) return nullptr;

    {
        std::ofstream f(tmp_path, std::ios::binary | std::ios::trunc);
        if (!f) {
            LOGE_B("Cannot write temp file: %s", tmp_path);
            return nullptr;
        }
        f.write(reinterpret_cast<const char*>(bytes), (std::streamsize)len);
    }

    std::string result;
    try {
        DocumentStorage store;
        RawBinaryArchitecture* arch =
            new RawBinaryArchitecture(tmp_path, "AARCH64:LE:64:v8A",
                                      &g_null_stream);
        arch->init(store);

        AddrSpace* ram = arch->getDefaultCodeSpace();
        Address funcAddr(ram, 0);

        Funcdata* fd = arch->symboltab->getGlobalScope()
                           ->addFunction(funcAddr, func_name)
                           ->getFunction();
        if (!fd) {
            LOGE_B("addFunction returned null for %s", func_name);
            delete arch;
            std::remove(tmp_path);
            return nullptr;
        }

        Address baddr(ram, 0);
        Address eaddr(ram, ram->getHighest());
        fd->followFlow(baddr, eaddr);

        arch->allacts.getCurrent()->reset(*fd);
        int4 res = arch->allacts.getCurrent()->perform(*fd);
        if (res >= 0) {
            std::ostringstream out;
            arch->print->setOutputStream(&out);
            arch->print->docFunction(fd);
            result = out.str();
            LOGI_B("Decompiled %s: %zu chars (res=%d)", func_name, result.size(), res);
        } else {
            LOGE_B("Decompile pipeline failed for %s (res=%d)", func_name, res);
        }

        delete arch;
    } catch (const LowlevelError& e) {
        LOGE_B("LowlevelError decompiling %s: %s", func_name, e.explain.c_str());
    } catch (const std::exception& e) {
        LOGE_B("Exception decompiling %s: %s", func_name, e.what());
    } catch (...) {
        LOGE_B("Unknown exception decompiling %s", func_name);
    }

    std::remove(tmp_path);

    if (result.empty()) return nullptr;

    char* ret = static_cast<char*>(malloc(result.size() + 1));
    if (ret) memcpy(ret, result.c_str(), result.size() + 1);
    return ret;
}

void peek_decompiler_shutdown(void) {
    if (g_init_ok) {
        SleighArchitecture::shutdown();
        g_init_ok = false;
    }
}

} // extern "C"
