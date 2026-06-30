#include "decompiler_bridge.h"
#include "peek_architecture.h"
#include "peek_scope.h"

#include "decompiler/libdecomp.hh"
#include "decompiler/database.hh"
#include "decompiler/fspec.hh"
#include "decompiler/type.hh"
#include "decompiler/funcdata.hh"

#include <android/log.h>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <sstream>
#include <streambuf>
#include <vector>

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
// Type helpers — map simplified type vocabulary to Ghidra Datatype*.
// All returned pointers are owned by the TypeFactory; do not delete them.
// ---------------------------------------------------------------------------

static Datatype* type_from_str(Architecture* arch, const char* s) {
    if (!s || s[0] == '\0' || strcmp(s, "unknown") == 0)
        return arch->types->getBase(1, TYPE_UNKNOWN);
    if (strcmp(s, "void") == 0)     return arch->types->getTypeVoid();
    if (strcmp(s, "bool") == 0)     return arch->types->getBase(1, TYPE_BOOL);
    if (strcmp(s, "int") == 0)      return arch->types->getBase(4, TYPE_INT);
    if (strcmp(s, "uint") == 0)     return arch->types->getBase(4, TYPE_UINT);
    if (strcmp(s, "long") == 0)     return arch->types->getBase(8, TYPE_INT);
    if (strcmp(s, "ulong") == 0 ||
        strcmp(s, "size_t") == 0)   return arch->types->getBase(8, TYPE_UINT);
    if (strcmp(s, "float") == 0)    return arch->types->getBase(4, TYPE_FLOAT);
    if (strcmp(s, "double") == 0)   return arch->types->getBase(8, TYPE_FLOAT);
    if (strcmp(s, "char*") == 0)
        return arch->types->getTypePointer(8, arch->types->getBase(1, TYPE_INT), 1);
    if (strcmp(s, "void*") == 0 ||
        strcmp(s, "ptr") == 0)
        return arch->types->getTypePointer(8, arch->types->getTypeVoid(), 1);
    // default: opaque 8-byte pointer
    return arch->types->getTypePointer(8, arch->types->getBase(1, TYPE_UNKNOWN), 1);
}

// ---------------------------------------------------------------------------
// Inject one callee signature via PeekScope::preRegisterFunction.
//
// Mirrors r2ghidra's approach exactly: register function in the scope's cache
// then lock the prototype.  Called after arch->init() and before followFlow.
// ---------------------------------------------------------------------------

static void inject_sig_into_scope(PeekScope*         peekScope,
                                   Architecture*      arch,
                                   AddrSpace*         ram,
                                   const PeekFuncSig& sig,
                                   uint64_t           skip_addr)
{
    if (sig.address == 0 || sig.address == skip_addr) return;
    if (!sig.name || sig.name[0] == '\0') return;

    Address sigAddr(ram, (uintb)sig.address);

    // preRegisterFunction writes into ScopeInternal (cache_) directly,
    // bypassing PeekScope::addSymbolInternal which throws.
    FunctionSymbol* fsym = peekScope->preRegisterFunction(sigAddr, sig.name);
    if (!fsym) return;

    bool has_ret    = sig.return_type && sig.return_type[0] != '\0';
    bool has_params = sig.param_count >= 0 &&
                      sig.params_csv  && sig.params_csv[0] != '\0';
    if (!has_ret && !has_params) return;

    Funcdata* callee = fsym->getFunction();
    if (!callee) return;

    try {
        PrototypePieces proto;
        proto.model           = arch->defaultfp;
        proto.name            = sig.name;
        proto.firstVarArgSlot = -1;

        proto.outtype = has_ret
            ? type_from_str(arch, sig.return_type)
            : arch->types->getBase(4, TYPE_INT);

        if (has_params && sig.param_count > 0) {
            std::string csv(sig.params_csv);
            size_t pos = 0;
            int parsed = 0;
            while (parsed < sig.param_count && pos <= csv.size()) {
                size_t comma = csv.find(',', pos);
                if (comma == std::string::npos) comma = csv.size();
                std::string tok = csv.substr(pos, comma - pos);
                proto.intypes.push_back(type_from_str(arch, tok.c_str()));
                proto.innames.push_back("param" + std::to_string(parsed + 1));
                pos = comma + 1;
                ++parsed;
            }
        }

        callee->getFuncProto().setPieces(proto);
        callee->getFuncProto().setInputLock(true);
        callee->getFuncProto().setOutputLock(true);
    } catch (...) {
        // A bad entry must not abort the whole decompilation.
    }
}

// ---------------------------------------------------------------------------
// Extract the prototype inferred by the decompiler for the target function.
//
// IMPORTANT: a printed return type of "void" is ambiguous on its own —
// see the extended comment in the original bridge for the full rationale.
// Only cache a prototype when a live RETURN op has a real data input.
// ---------------------------------------------------------------------------

static void extract_inferred(const Funcdata* fd, PeekInferredSig* out) {
    if (!fd || !out) return;
    out->is_set      = 0;
    out->param_count = 0;
    out->return_type[0] = '\0';
    out->params_csv[0]  = '\0';

    try {
        const FuncProto& fp = fd->getFuncProto();
        Datatype* ret = fp.getOutputType();
        bool ret_is_void = !ret || ret->getMetatype() == TYPE_VOID;

        if (ret_is_void) {
            PcodeOp* retop = fd->getFirstReturnOp();
            if (!retop || retop->numInput() > 1) return;
            // No live data input on the return — ambiguous void; don't cache.
            return;
        }

        std::string rname = ret->getName();
        snprintf(out->return_type, sizeof(out->return_type), "%s", rname.c_str());

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
            snprintf(out->params_csv, sizeof(out->params_csv), "%s", csv.c_str());
        }
        out->is_set = 1;
    } catch (...) {
        out->is_set = 0;
    }
}

// ---------------------------------------------------------------------------
// Tail-call rewrite.
//
// An unconditional B used as the last instruction of a function (tail call)
// causes followFlow to see flow leaving [baddr,eaddr) with no return — no
// live RETURN op exists.  Fix: flip bit 31 of the B to produce a BL with
// the same target, then append a synthetic RET so control has somewhere to
// return to.  Only applied when the target matches a known callee in sigs[].
// ---------------------------------------------------------------------------

static bool rewrite_tail_call(std::vector<uint8_t>& buf, uint64_t base_addr,
                               const PeekFuncSig*  sigs, size_t sig_count) {
    if (buf.size() < 4) return false;
    size_t last = buf.size() - 4;
    uint32_t w;
    std::memcpy(&w, buf.data() + last, 4);

    // Unconditional B: top 6 bits == 000101.  (BL = 100101; B.cond = 0101010.)
    uint32_t top6 = (w >> 26) & 0x3F;
    if (top6 != 0b000101) return false;

    int32_t imm26 = (int32_t)(w & 0x3FFFFFF);
    if (imm26 & 0x2000000) imm26 -= 0x4000000;
    uint64_t insn_addr = base_addr + (uint64_t)last;
    uint64_t target    = insn_addr + (uint64_t)((int64_t)imm26 * 4);

    bool target_known = false;
    for (size_t i = 0; i < sig_count; ++i)
        if (sigs[i].address == target) { target_known = true; break; }
    if (!target_known) return false;

    uint32_t bl_word = w | (1u << 31);
    std::memcpy(buf.data() + last, &bl_word, 4);
    static const uint8_t ret_bytes[4] = {0xC0, 0x03, 0x5F, 0xD6};
    buf.insert(buf.end(), ret_bytes, ret_bytes + 4);
    return true;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

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

void peek_decompiler_shutdown(void) {}

// ---------------------------------------------------------------------------
// Primary decompile entry point — r2ghidra-style PeekScope architecture.
// ---------------------------------------------------------------------------

char* peek_decompile_elf(
    const ElfParseResult& elf,
    const char*           func_name,
    uint64_t              real_func_addr,
    uint64_t              func_len,
    const PeekFuncSig*    sigs,
    size_t                sig_count,
    PeekInferredSig*      out_inferred)
{
    g_last_error.clear();
    if (out_inferred) out_inferred->is_set = 0;

    if (!g_init_ok)
        return fail("[init]", func_name, "decompiler library not initialised");
    if (func_len == 0)
        return fail("[init]", func_name, "function byte length is zero");

    // ------------------------------------------------------------------
    // Stage 0.5 — optional tail-call rewrite (B → BL + synthetic RET).
    // Copy the function bytes from the ELF for the rewrite check only;
    // the result is used as a patch overlay on PeekLoadImage.
    // ------------------------------------------------------------------
    std::vector<uint8_t> work;
    uint64_t effective_len = func_len;

    for (const auto& sec : elf.sections) {
        if (!sec.is_executable()) continue;
        if (real_func_addr <  sec.address ||
            real_func_addr >= sec.address + sec.size) continue;
        const uint64_t off      = real_func_addr - sec.address;
        const uint64_t avail    = sec.size - off;
        const uint64_t copy_len = std::min(func_len, avail);
        const uint64_t file_off = sec.offset + off;
        if (file_off + copy_len > elf.data.size()) break;
        work.assign(elf.data.begin() + file_off,
                    elf.data.begin() + file_off + copy_len);
        break;
    }

    bool tail_call_rewritten = false;
    if (!work.empty() && sigs && sig_count > 0) {
        tail_call_rewritten = rewrite_tail_call(work, real_func_addr,
                                                sigs, sig_count);
        if (tail_call_rewritten) {
            effective_len = (uint64_t)work.size();  // func_len + 4 (synthetic RET)
            LOGI_B("[S0.5] rewrote tail-call B->BL+RET for %s (effective_len=%llu)",
                   func_name, (unsigned long long)effective_len);
        }
    }

    std::string result;
    PeekArchitecture* arch = nullptr;
    try {
        // ------------------------------------------------------------------
        // Stage 2 — construct PeekArchitecture (installs PeekScope +
        // PeekLoadImage).  No temp file — PeekLoadImage reads directly from
        // the ElfParseResult byte vector.
        // ------------------------------------------------------------------
        LOGI_B("[S2] constructing PeekArchitecture for %s", func_name);
        DocumentStorage store;
        try {
            arch = new PeekArchitecture(elf, &g_null_stream);
            // Register patch before init() so buildLoader() picks it up.
            if (tail_call_rewritten)
                arch->setPatch(work.data(), real_func_addr, work.size());
            arch->init(store);
            LOGI_B("[S2] arch init OK for %s", func_name);
        } catch (const LowlevelError& e) {
            return fail("[S2:arch_init]", func_name, e.explain.c_str());
        } catch (const std::exception& e) {
            return fail("[S2:arch_init]", func_name, e.what());
        }

        AddrSpace* ram = arch->getDefaultCodeSpace();
        if (!ram) {
            delete arch;
            return fail("[S2:getDefaultCodeSpace]", func_name,
                        "default code space is null after init()");
        }

        PeekScope* peekScope = arch->getPeekScope();
        if (!peekScope) {
            delete arch;
            return fail("[S2:getPeekScope]", func_name,
                        "PeekScope not installed");
        }

        // ------------------------------------------------------------------
        // Stage 2.5 — inject typed callee signatures via preRegisterFunction.
        //
        // PeekScope::addSymbolInternal throws intentionally (mirrors R2Scope).
        // preRegisterFunction bypasses it and writes into the internal
        // ScopeInternal cache directly — the on-demand lookup path then
        // finds those entries on first access without re-querying the ELF.
        // ------------------------------------------------------------------
        if (sigs && sig_count > 0) {
            LOGI_B("[S2.5] injecting %zu signatures for %s", sig_count, func_name);
            size_t injected = 0;
            for (size_t i = 0; i < sig_count; ++i) {
                try {
                    inject_sig_into_scope(peekScope, arch, ram, sigs[i],
                                          real_func_addr);
                    ++injected;
                } catch (...) {}
            }
            LOGI_B("[S2.5] injected %zu/%zu sigs for %s",
                   injected, sig_count, func_name);
        }

        // ------------------------------------------------------------------
        // Stage 3 — register target function + followFlow.
        //
        // preRegisterFunction writes into ScopeInternal (cache_); when
        // followFlow's flow analysis calls peekScope->findFunction(funcAddr)
        // to locate the Funcdata, it hits the cache first and returns
        // immediately — no ELF re-query needed for the target itself.
        // ------------------------------------------------------------------
        LOGI_B("[S3] preRegisterFunction + followFlow for %s "
               "(addr=0x%llx len=%llu effective=%llu)",
               func_name,
               (unsigned long long)real_func_addr,
               (unsigned long long)func_len,
               (unsigned long long)effective_len);

        Funcdata* fd = nullptr;
        try {
            Address funcAddr(ram, (uintb)real_func_addr);
            FunctionSymbol* fsym = peekScope->preRegisterFunction(funcAddr, func_name);
            if (!fsym) {
                delete arch;
                return fail("[S3:preRegister]", func_name,
                            "preRegisterFunction returned null");
            }
            fd = fsym->getFunction();
            if (!fd) {
                delete arch;
                return fail("[S3:getFunction]", func_name,
                            "getFunction() returned null Funcdata");
            }

            Address baddr(ram, (uintb)real_func_addr);
            Address eaddr(ram, (uintb)(real_func_addr + effective_len - 1));
            LOGI_B("[S3] followFlow baddr=0x%llx eaddr=0x%llx",
                   (unsigned long long)real_func_addr,
                   (unsigned long long)(real_func_addr + effective_len - 1));
            fd->followFlow(baddr, eaddr);
            LOGI_B("[S3] followFlow OK for %s", func_name);

            // ----------------------------------------------------------------
            // Stage 3.5 — minimal self-prototype fallback.
            //
            // The target function itself is excluded from sigs[] by the caller
            // (peek_jni.cpp skips the self address), so fd has no output lock
            // after followFlow. Without a lock, ActionDeadCode may eliminate
            // the value flowing into this function's RETURN, producing an empty
            // body with no return statement even for functions that truly return
            // a value (e.g. "return sys-register-read" with no other consumer).
            //
            // Before locking anything: check whether raw p-code (pre-pipeline)
            // ever writes to the model's output storage. If it doesn't, the
            // function is genuinely void and we leave it alone.
            // ----------------------------------------------------------------
            bool self_sig_supplied = false;
            if (sigs) {
                for (size_t i = 0; i < sig_count; ++i) {
                    if (sigs[i].address == real_func_addr) {
                        self_sig_supplied = true; break;
                    }
                }
            }
            if (!self_sig_supplied && !fd->getFuncProto().isOutputLocked()) {
                try {
                    PrototypePieces probe;
                    probe.model           = arch->defaultfp;
                    probe.name            = func_name;
                    probe.firstVarArgSlot = -1;
                    probe.outtype         = arch->types->getBase(8, TYPE_UNKNOWN);
                    std::vector<ParameterPieces> resolved;
                    arch->defaultfp->assignParameterStorage(probe, resolved, true);

                    bool wrote_to_output = false;
                    if (!resolved.empty() && !resolved[0].addr.isInvalid()) {
                        const Address& outAddr = resolved[0].addr;
                        int4 outSize = resolved[0].type
                            ? resolved[0].type->getSize() : 8;
                        for (auto iter = fd->beginOpAlive(); iter != fd->endOpAlive(); ++iter) {
                            PcodeOp* op = *iter;
                            Varnode* outvn = op->getOut();
                            if (!outvn) continue;
                            if (outvn->getAddr().overlap(0, outAddr, outSize) != -1) {
                                wrote_to_output = true; break;
                            }
                        }
                    }

                    if (wrote_to_output) {
                        PrototypePieces proto;
                        proto.model           = arch->defaultfp;
                        proto.name            = func_name;
                        proto.firstVarArgSlot = -1;
                        proto.outtype         = arch->types->getBase(8, TYPE_UNKNOWN);
                        fd->getFuncProto().setPieces(proto);
                        fd->getFuncProto().setOutputLock(true);
                        LOGI_B("[S3.5] applied self-output lock for %s", func_name);
                    } else {
                        LOGI_B("[S3.5] skipped self-output lock for %s "
                               "(void-consistent)", func_name);
                    }
                } catch (...) {}
            }

        } catch (const LowlevelError& e) {
            std::ostringstream detail;
            detail << e.explain << " [func=0x" << std::hex << real_func_addr
                   << "+0x" << func_len << "]";
            delete arch;
            return fail("[S3:followFlow]", func_name, detail.str().c_str());
        } catch (const std::exception& e) {
            delete arch;
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
                std::ostringstream detail;
                detail << "perform() returned " << res;
                delete arch;
                return fail("[S4:pipeline]", func_name, detail.str().c_str());
            }
            LOGI_B("[S4] pipeline OK for %s (res=%d)", func_name, res);
            extract_inferred(fd, out_inferred);
        } catch (const LowlevelError& e) {
            delete arch;
            return fail("[S4:pipeline]", func_name, e.explain.c_str());
        } catch (const std::exception& e) {
            delete arch;
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
            LOGI_B("[S5] docFunction OK for %s: %zu chars",
                   func_name, result.size());
        } catch (const LowlevelError& e) {
            delete arch;
            return fail("[S5:docFunction]", func_name, e.explain.c_str());
        } catch (const std::exception& e) {
            delete arch;
            return fail("[S5:docFunction]", func_name, e.what());
        }

        delete arch;

    } catch (const LowlevelError& e) {
        if (arch) delete arch;
        return fail("[unknown_stage]", func_name, e.explain.c_str());
    } catch (const std::exception& e) {
        if (arch) delete arch;
        return fail("[unknown_stage]", func_name, e.what());
    } catch (...) {
        if (arch) delete arch;
        return fail("[unknown_stage]", func_name, "unknown C++ exception");
    }

    if (result.empty())
        return fail("[S5:docFunction]", func_name, "output was empty");

    char* ret = static_cast<char*>(malloc(result.size() + 1));
    if (ret) memcpy(ret, result.c_str(), result.size() + 1);
    return ret;
}
