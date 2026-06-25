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

// Thread-local error string — set on every failure path so the JNI layer can
// retrieve a meaningful message rather than just "nullptr".
thread_local std::string g_last_error;

// Helper: set the thread-local error, emit it to logcat, and return nullptr.
static char* fail(const char* stage, const char* func, const char* detail) {
    std::ostringstream ss;
    ss << stage << " failed for " << func << ": " << detail;
    g_last_error = ss.str();
    LOGE_B("%s", g_last_error.c_str());
    return nullptr;
}

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

const char* peek_decompile_get_last_error(void) {
    return g_last_error.c_str();
}

char* peek_decompile_bytes(const uint8_t* bytes, size_t len,
                            const char* func_name, const char* tmp_path) {
    g_last_error.clear();

    if (!g_init_ok) {
        return fail("[init]", func_name, "decompiler library not initialised");
    }
    if (!bytes || len == 0) {
        return fail("[init]", func_name, "null/empty byte buffer");
    }

    // ------------------------------------------------------------------
    // Stage 1 — write raw bytes to a temp file for RawLoadImage
    // ------------------------------------------------------------------
    LOGI_B("[S1] writing %zu bytes to %s for %s", len, tmp_path, func_name);
    {
        std::ofstream f(tmp_path, std::ios::binary | std::ios::trunc);
        if (!f) {
            return fail("[S1:write_temp]", func_name, tmp_path);
        }
        f.write(reinterpret_cast<const char*>(bytes), (std::streamsize)len);
    }

    std::string result;
    RawBinaryArchitecture* arch = nullptr;
    try {
        // ------------------------------------------------------------------
        // Stage 2 — construct Architecture + load SLEIGH spec
        // ------------------------------------------------------------------
        LOGI_B("[S2] constructing RawBinaryArchitecture for %s", func_name);
        DocumentStorage store;
        try {
            arch = new RawBinaryArchitecture(tmp_path, "AARCH64:LE:64:v8A",
                                             &g_null_stream);
            arch->init(store);
            LOGI_B("[S2] arch init OK for %s", func_name);
        } catch (const LowlevelError& e) {
            std::remove(tmp_path);
            return fail("[S2:arch_init]", func_name, e.explain.c_str());
        } catch (const std::exception& e) {
            std::remove(tmp_path);
            return fail("[S2:arch_init]", func_name, e.what());
        }

        AddrSpace* ram = arch->getDefaultCodeSpace();
        Address funcAddr(ram, 0);

        // ------------------------------------------------------------------
        // Stage 3 — register function symbol + followFlow (SLEIGH lift)
        //
        // Key: eaddr is bounded to the function's own byte range so that
        // PC-relative branches whose targets were encoded against the
        // original VA (not 0) don't wrap around into garbage addresses and
        // cause followFlow to attempt disassembly outside the loaded image.
        // ------------------------------------------------------------------
        LOGI_B("[S3] addFunction + followFlow for %s (len=%zu)", func_name, len);
        Funcdata* fd = nullptr;
        try {
            fd = arch->symboltab->getGlobalScope()
                     ->addFunction(funcAddr, func_name)
                     ->getFunction();
            if (!fd) {
                delete arch;
                std::remove(tmp_path);
                return fail("[S3:addFunction]", func_name, "returned null Funcdata");
            }

            Address baddr(ram, 0);
            // Exclusive upper bound: restrict flow analysis to the function
            // body only.  Using ram->getHighest() here is wrong for raw
            // images because PC-relative branch encodings are relative to
            // the original VA, not to address 0, so out-of-body targets
            // can wrap into the huge address space and trigger SLEIGH to
            // attempt disassembly of garbage bytes.
            Address eaddr(ram, (uintb)(len - 1));
            fd->followFlow(baddr, eaddr);
            LOGI_B("[S3] followFlow OK for %s", func_name);
        } catch (const LowlevelError& e) {
            delete arch;
            std::remove(tmp_path);
            return fail("[S3:followFlow]", func_name, e.explain.c_str());
        } catch (const std::exception& e) {
            delete arch;
            std::remove(tmp_path);
            return fail("[S3:followFlow]", func_name, e.what());
        }

        // ------------------------------------------------------------------
        // Stage 4 — action pipeline (type recovery, SSA, simplification)
        // ------------------------------------------------------------------
        LOGI_B("[S4] running action pipeline for %s", func_name);
        try {
            Action* pipeline = arch->allacts.getCurrent();
            pipeline->reset(*fd);
            int4 res = pipeline->perform(*fd);
            if (res < 0) {
                delete arch;
                std::remove(tmp_path);
                std::ostringstream detail;
                detail << "perform() returned " << res;
                return fail("[S4:pipeline]", func_name, detail.str().c_str());
            }
            LOGI_B("[S4] pipeline OK for %s (res=%d)", func_name, res);
        } catch (const LowlevelError& e) {
            delete arch;
            std::remove(tmp_path);
            return fail("[S4:pipeline]", func_name, e.explain.c_str());
        } catch (const std::exception& e) {
            delete arch;
            std::remove(tmp_path);
            return fail("[S4:pipeline]", func_name, e.what());
        }

        // ------------------------------------------------------------------
        // Stage 5 — code generation (C pseudocode pretty-print)
        // ------------------------------------------------------------------
        LOGI_B("[S5] docFunction for %s", func_name);
        try {
            std::ostringstream out;
            arch->print->setOutputStream(&out);
            arch->print->docFunction(fd);
            result = out.str();
            LOGI_B("[S5] docFunction OK for %s: %zu chars", func_name, result.size());
        } catch (const LowlevelError& e) {
            delete arch;
            std::remove(tmp_path);
            return fail("[S5:docFunction]", func_name, e.explain.c_str());
        } catch (const std::exception& e) {
            delete arch;
            std::remove(tmp_path);
            return fail("[S5:docFunction]", func_name, e.what());
        }

        delete arch;

    } catch (const LowlevelError& e) {
        if (arch) delete arch;
        std::remove(tmp_path);
        return fail("[unknown_stage]", func_name, e.explain.c_str());
    } catch (const std::exception& e) {
        if (arch) delete arch;
        std::remove(tmp_path);
        return fail("[unknown_stage]", func_name, e.what());
    } catch (...) {
        if (arch) delete arch;
        std::remove(tmp_path);
        return fail("[unknown_stage]", func_name, "unknown C++ exception");
    }

    std::remove(tmp_path);

    if (result.empty()) {
        return fail("[S5:docFunction]", func_name, "output was empty");
    }

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
