#include "decompiler_bridge.h"

#include "decompiler/libdecomp.hh"
#include "decompiler/raw_arch.hh"
#include "decompiler/database.hh"
#include "decompiler/fspec.hh"
#include "decompiler/type.hh"
#include "decompiler/funcdata.hh"

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

thread_local std::string g_last_error;

static char* fail(const char* stage, const char* func, const char* detail) {
    std::ostringstream ss;
    ss << stage << " failed for " << func << ": " << detail;
    g_last_error = ss.str();
    LOGE_B("%s", g_last_error.c_str());
    return nullptr;
}

// ---------------------------------------------------------------------------
// Type helpers — map the simplified type vocabulary to Ghidra Datatype*.
// All returned pointers are owned by the TypeFactory; do not delete them.
// ---------------------------------------------------------------------------

static Datatype* type_from_str(Architecture* arch, const char* s) {
    if (!s || s[0] == '\0' || strcmp(s, "unknown") == 0)
        return arch->types->getBase(1, TYPE_UNKNOWN);
    if (strcmp(s, "void") == 0)
        return arch->types->getTypeVoid();
    if (strcmp(s, "bool") == 0)
        return arch->types->getBase(1, TYPE_BOOL);
    if (strcmp(s, "int") == 0)
        return arch->types->getBase(4, TYPE_INT);
    if (strcmp(s, "uint") == 0)
        return arch->types->getBase(4, TYPE_UINT);
    if (strcmp(s, "long") == 0)
        return arch->types->getBase(8, TYPE_INT);
    if (strcmp(s, "ulong") == 0 || strcmp(s, "size_t") == 0)
        return arch->types->getBase(8, TYPE_UINT);
    if (strcmp(s, "float") == 0)
        return arch->types->getBase(4, TYPE_FLOAT);
    if (strcmp(s, "double") == 0)
        return arch->types->getBase(8, TYPE_FLOAT);
    if (strcmp(s, "char*") == 0)
        return arch->types->getTypePointer(8, arch->types->getBase(1, TYPE_INT), 1);
    if (strcmp(s, "void*") == 0 || strcmp(s, "ptr") == 0)
        return arch->types->getTypePointer(8, arch->types->getTypeVoid(), 1);
    // default: opaque 8-byte pointer
    return arch->types->getTypePointer(8, arch->types->getBase(1, TYPE_UNKNOWN), 1);
}

// ---------------------------------------------------------------------------
// Inject one function signature into the arch's global scope.
//
// Called with the arch fully initialised (after arch->init()) but before
// followFlow so that the decompiler can look up callee names and types.
// Addresses outside the loaded region are fine — Ghidra only needs them in
// the symbol table; it won't try to lift their bytes.
// ---------------------------------------------------------------------------

static void inject_sig(Architecture* arch,
                        AddrSpace*    ram,
                        const PeekFuncSig& sig,
                        uint64_t      skip_addr)
{
    if (sig.address == 0 || sig.address == skip_addr) return;
    if (!sig.name || sig.name[0] == '\0') return;

    Address sigAddr(ram, (uintb)sig.address);
    Scope* scope = arch->symboltab->getGlobalScope();

    FunctionSymbol* fsym = scope->addFunction(sigAddr, sig.name);
    if (!fsym) return;

    // If we have type information, set the callee's prototype so the
    // decompiler can propagate return values and argument types across
    // the call site.
    bool has_ret    = sig.return_type  && sig.return_type[0] != '\0';
    bool has_params = sig.param_count >= 0 &&
                      sig.params_csv   && sig.params_csv[0] != '\0';

    if (!has_ret && !has_params) return;

    Funcdata* callee = fsym->getFunction();
    if (!callee) return;

    try {
        PrototypePieces proto;
        proto.model          = arch->defaultfp;
        proto.name           = sig.name;
        proto.firstVarArgSlot = -1;

        // Return type
        proto.outtype = has_ret
            ? type_from_str(arch, sig.return_type)
            : arch->types->getBase(4, TYPE_INT);  // fallback: int

        // Parameters — parse the CSV
        if (has_params && sig.param_count > 0) {
            std::string csv(sig.params_csv);
            size_t pos = 0;
            int parsed = 0;
            while (parsed < sig.param_count && pos <= csv.size()) {
                size_t comma = csv.find(',', pos);
                if (comma == std::string::npos) comma = csv.size();
                std::string tok = csv.substr(pos, comma - pos);
                proto.intypes.push_back(type_from_str(arch, tok.c_str()));
                // Use generic param names — sufficient for type propagation.
                proto.innames.push_back("param" + std::to_string(parsed + 1));
                pos = comma + 1;
                ++parsed;
            }
        }
        // If param_count == 0 and no CSV, leave intypes empty → void params.

        callee->getFuncProto().setPieces(proto);
        // Lock the prototype so the action pipeline doesn't override our
        // externally-supplied information with its own inference.
        callee->getFuncProto().setInputLock(true);
        callee->getFuncProto().setOutputLock(true);
    } catch (...) {
        // A bad entry must not abort the whole decompilation.
    }
}

// ---------------------------------------------------------------------------
// Extract the prototype that the decompiler inferred for the target function.
// Stored in simplified vocabulary for the DB; used for lazy learning.
// ---------------------------------------------------------------------------

static void extract_inferred(const Funcdata* fd, PeekInferredSig* out) {
    if (!fd || !out) return;
    out->is_set      = 0;
    out->param_count = 0;
    out->return_type[0] = '\0';
    out->params_csv[0]  = '\0';

    try {
        const FuncProto& fp = fd->getFuncProto();

        // Return type
        Datatype* ret = fp.getOutputType();
        if (ret) {
            std::string rname = ret->getName();
            snprintf(out->return_type, sizeof(out->return_type),
                     "%s", rname.c_str());
        }

        // Parameters
        int np = fp.numParams();
        out->param_count = np;
        if (np > 0) {
            std::string csv;
            int cap = (np < 16) ? np : 16;
            for (int pi = 0; pi < cap; ++pi) {
                ProtoParameter* pp = fp.getParam(pi);
                if (!pp) continue;
                Datatype* pt = pp->getType();
                if (pt) {
                    if (!csv.empty()) csv += ',';
                    csv += pt->getName();
                }
            }
            snprintf(out->params_csv, sizeof(out->params_csv),
                     "%s", csv.c_str());
        }

        out->is_set = 1;
    } catch (...) {
        out->is_set = 0;
    }
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Public C API
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// V2 — full implementation with signature injection
// ---------------------------------------------------------------------------

char* peek_decompile_bytes_v2(const uint8_t* bytes, size_t len,
                               const char*    func_name,
                               const char*    tmp_path,
                               uint64_t       real_func_addr,
                               const PeekFuncSig* sigs,
                               size_t         sig_count,
                               PeekInferredSig*   out_inferred)
{
    g_last_error.clear();
    if (out_inferred) out_inferred->is_set = 0;

    if (!g_init_ok)
        return fail("[init]", func_name, "decompiler library not initialised");
    if (!bytes || len == 0)
        return fail("[init]", func_name, "null/empty byte buffer");

    // ------------------------------------------------------------------
    // Stage 1 — write raw bytes to a temp file for RawLoadImage
    // ------------------------------------------------------------------
    LOGI_B("[S1] writing %zu bytes to %s for %s", len, tmp_path, func_name);
    {
        std::ofstream f(tmp_path, std::ios::binary | std::ios::trunc);
        if (!f) return fail("[S1:write_temp]", func_name, tmp_path);
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
            arch->adjustvma = (long)real_func_addr;
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
        if (!ram) {
            delete arch; std::remove(tmp_path);
            return fail("[S2:getDefaultCodeSpace]", func_name,
                        "default code space is null after init()");
        }

        // Range check
        uintb highest = ram->getHighest();
        if ((uintb)real_func_addr > highest ||
            (len > 0 && (uintb)(real_func_addr + len - 1) > highest)) {
            delete arch; std::remove(tmp_path);
            std::ostringstream oss;
            oss << "function range [0x" << std::hex << real_func_addr
                << ", 0x" << (real_func_addr + len - 1)
                << "] exceeds address space highest 0x" << highest;
            return fail("[S3:range_check]", func_name, oss.str().c_str());
        }

        // ------------------------------------------------------------------
        // Stage 2.5 — inject cross-function signatures
        //
        // Populate the global scope with prototypes for every known function
        // BEFORE followFlow is called.  Ghidra resolves call targets by
        // searching the scope at the call-target address, so pre-populating
        // the scope turns "(**(code **)0x12345678)(...)" into a named call
        // with (optionally) correctly typed parameters and return value.
        //
        // This must happen after arch->init() (so the type system and spec
        // files are loaded) but before addFunction + followFlow (so that
        // the scope is ready when flow analysis resolves call edges).
        // ------------------------------------------------------------------
        if (sigs && sig_count > 0) {
            LOGI_B("[S2.5] injecting %zu signatures for %s", sig_count, func_name);
            size_t injected = 0;
            for (size_t i = 0; i < sig_count; ++i) {
                try {
                    inject_sig(arch, ram, sigs[i], real_func_addr);
                    ++injected;
                } catch (...) {
                    // A bad entry must not abort the whole decompilation.
                }
            }
            LOGI_B("[S2.5] injected %zu/%zu signatures for %s",
                   injected, sig_count, func_name);
        }

        // ------------------------------------------------------------------
        // Stage 3 — register target function symbol + followFlow
        // ------------------------------------------------------------------
        LOGI_B("[S3] addFunction + followFlow for %s (addr=0x%llx len=%zu)",
               func_name, (unsigned long long)real_func_addr, len);
        Funcdata* fd = nullptr;
        try {
            Address funcAddr(ram, (uintb)real_func_addr);
            fd = arch->symboltab->getGlobalScope()
                     ->addFunction(funcAddr, func_name)
                     ->getFunction();
            if (!fd) {
                delete arch; std::remove(tmp_path);
                return fail("[S3:addFunction]", func_name, "returned null Funcdata");
            }

            Address baddr(ram, (uintb)real_func_addr);
            Address eaddr(ram, (uintb)(real_func_addr + len - 1));
            LOGI_B("[S3] followFlow baddr=0x%llx eaddr=0x%llx for %s",
                   (unsigned long long)real_func_addr,
                   (unsigned long long)(real_func_addr + len - 1),
                   func_name);
            fd->followFlow(baddr, eaddr);
            LOGI_B("[S3] followFlow OK for %s", func_name);
        } catch (const LowlevelError& e) {
            delete arch; std::remove(tmp_path);
            std::ostringstream detail;
            detail << e.explain
                   << " [func=0x" << std::hex << real_func_addr
                   << "+0x" << len << "]";
            return fail("[S3:followFlow]", func_name, detail.str().c_str());
        } catch (const std::exception& e) {
            delete arch; std::remove(tmp_path);
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
                delete arch; std::remove(tmp_path);
                std::ostringstream detail;
                detail << "perform() returned " << res;
                return fail("[S4:pipeline]", func_name, detail.str().c_str());
            }
            LOGI_B("[S4] pipeline OK for %s (res=%d)", func_name, res);

            // Extract the prototype the decompiler inferred — for lazy learning.
            extract_inferred(fd, out_inferred);
        } catch (const LowlevelError& e) {
            delete arch; std::remove(tmp_path);
            return fail("[S4:pipeline]", func_name, e.explain.c_str());
        } catch (const std::exception& e) {
            delete arch; std::remove(tmp_path);
            return fail("[S4:pipeline]", func_name, e.what());
        }

        // ------------------------------------------------------------------
        // Stage 5 — code generation
        // ------------------------------------------------------------------
        LOGI_B("[S5] docFunction for %s", func_name);
        try {
            std::ostringstream out;
            arch->print->setOutputStream(&out);
            arch->print->docFunction(fd);
            result = out.str();
            LOGI_B("[S5] docFunction OK for %s: %zu chars", func_name, result.size());
        } catch (const LowlevelError& e) {
            delete arch; std::remove(tmp_path);
            return fail("[S5:docFunction]", func_name, e.explain.c_str());
        } catch (const std::exception& e) {
            delete arch; std::remove(tmp_path);
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

    if (result.empty())
        return fail("[S5:docFunction]", func_name, "output was empty");

    char* ret = static_cast<char*>(malloc(result.size() + 1));
    if (ret) memcpy(ret, result.c_str(), result.size() + 1);
    return ret;
}

// ---------------------------------------------------------------------------
// V1 — backwards-compatible wrapper
// ---------------------------------------------------------------------------

char* peek_decompile_bytes(const uint8_t* bytes, size_t len,
                            const char* func_name, const char* tmp_path,
                            uint64_t real_func_addr)
{
    return peek_decompile_bytes_v2(bytes, len, func_name, tmp_path,
                                   real_func_addr,
                                   nullptr, 0, nullptr);
}

void peek_decompiler_shutdown(void) {
    if (g_init_ok) {
        SleighArchitecture::shutdown();
        g_init_ok = false;
    }
}

} // extern "C"
