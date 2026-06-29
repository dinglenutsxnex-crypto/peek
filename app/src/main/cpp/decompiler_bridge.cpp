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
//
// IMPORTANT: a printed return type of "void" is ambiguous on its own — it is
// indistinguishable from a case where the real return value was computed by
// something this isolated, per-function decompile couldn't resolve (a call
// to a sibling function outside [baddr,eaddr], or a system-register read),
// got dead-code-eliminated as a result, and left nothing for Ghidra's own
// ActionOutputPrototype to see. Caching that as a learned "void" signature
// and then locking it onto every future caller (via setOutputLock in
// inject_sig) would actively make things worse on the next decompile, not
// better — the exact failure this lazy-learning cache is supposed to avoid.
//
// getFirstReturnOp() gives the actual CPUI_RETURN p-code op; numInput() > 1
// means a real data value reached the return (index 0 is just the
// return-address slot). If no live RETURN op carries a data input, we treat
// the inferred prototype as unusable and leave is_set = 0 rather than
// caching a possibly-false "void".
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
        bool ret_is_void = !ret || ret->getMetatype() == TYPE_VOID;

        if (ret_is_void) {
            // Could be a real void function, or DCE-eaten output. Check
            // whether any live RETURN op actually carried a data value —
            // if so, something is inconsistent (treat as unusable rather
            // than guess); if every RETURN op is data-less too, look at
            // whether the function has any RETURN at all to decide.
            PcodeOp* retop = fd->getFirstReturnOp();
            if (retop == nullptr) {
                // No live return at all (e.g. noreturn/abort-style or a
                // pipeline bail) — nothing trustworthy to learn.
                return;
            }
            if (retop->numInput() > 1) {
                // A data value reached the return op, but getOutputType()
                // still says void — inconsistent state, don't trust it.
                return;
            }
            // No data input on the only return op. This is the ambiguous
            // case described above: do not cache "void" from here. A
            // genuinely void function will simply have no entry learned,
            // which is harmless (inject_sig only locks a prototype when
            // it has real type info; an absent entry just means future
            // callers fall back to inference for this callee, same as
            // today, not worse).
            return;
        }

        std::string rname = ret->getName();
        snprintf(out->return_type, sizeof(out->return_type),
                 "%s", rname.c_str());

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

// ---------------------------------------------------------------------------
// Tail-call rewrite.
//
// This bridge decompiles exactly one function's bytes in isolation
// ([baddr,eaddr) only — see Stage 2). A normal call (BL ... ; <code continues
// after>) works fine: flow returns to the instruction after the BL, which is
// still inside the range, and the call site gets typed via inject_sig.
//
// A *tail call* — a plain, unconditional B as a function's last instruction,
// jumping directly to a sibling function's address instead of falling
// through to a RET — has no "after the call" to return to. followFlow sees
// this as flow leaving [baddr,eaddr) and, since FlowInfo::handleOutOfBounds
// has neither ignore_outofbounds nor error_outofbounds set, it warns and
// truncates that block with no successor and no return value — there is no
// live RETURN op left for anything (including the Stage 3.5 self-output
// lock) to anchor a value on. Real Ghidra never hits this: a whole-binary
// load never leaves the analyzed range, so a tail B just flows into the
// callee's own body and its own RET handles everything normally.
//
// Fix: detect this exact shape and rewrite it before Sleigh ever sees the
// bytes. B and BL differ by exactly one bit (bit 31) with an identical
// 26-bit target field, so flipping that bit preserves the branch target
// precisely while turning it into a real call instruction. We then append a
// synthetic RET so there is somewhere for control to return to. This is only
// applied when:
//   (a) the last 4 bytes decode as an unconditional B (top 6 bits 000101),
//       not a BL (top 6 bits 100101) and not any conditional/B.cond form,
//   (b) the computed target address matches a known sibling function in
//       sigs[] — i.e. we have positive evidence this is a real call to a
//       function we can name and type, not a guess about an arbitrary jump.
// Anything else (computed branches, targets with no matching signature,
// non-B-shaped tail instructions) is left completely untouched.
// ---------------------------------------------------------------------------

static bool rewrite_tail_call(std::vector<uint8_t>& buf, uint64_t base_addr,
                               const PeekFuncSig* sigs, size_t sig_count) {
    if (buf.size() < 4) return false;
    size_t last = buf.size() - 4;
    uint32_t w;
    std::memcpy(&w, buf.data() + last, 4);

    // Unconditional B: top 6 bits == 000101. (BL is 100101; B.cond is 0101010.)
    uint32_t top6 = (w >> 26) & 0x3F;
    if (top6 != 0b000101) return false;

    int32_t imm26 = (int32_t)(w & 0x3FFFFFF);
    if (imm26 & 0x2000000) imm26 -= 0x4000000;  // sign-extend
    uint64_t insn_addr = base_addr + (uint64_t)last;
    uint64_t target = insn_addr + (uint64_t)((int64_t)imm26 * 4);

    bool target_known = false;
    for (size_t i = 0; i < sig_count; ++i) {
        if (sigs[i].address == target) { target_known = true; break; }
    }
    if (!target_known) return false;

    // Flip bit 31: B -> BL, identical imm26, identical target.
    uint32_t bl_word = w | (1u << 31);
    std::memcpy(buf.data() + last, &bl_word, 4);

    // Append a RET (0xD65F03C0) so the call has somewhere to return to.
    static const uint8_t ret_bytes[4] = {0xC0, 0x03, 0x5F, 0xD6};
    buf.insert(buf.end(), ret_bytes, ret_bytes + 4);
    return true;
}

char* peek_decompile_bytes_v3(const uint8_t*     bytes,
                               size_t             len,
                               const char*        func_name,
                               const char*        tmp_path,
                               uint64_t           real_func_addr,
                               const PeekFuncSig* sigs,
                               size_t             sig_count,
                               const PeekDataSym* dsyms,
                               size_t             dsym_count,
                               PeekInferredSig*   out_inferred)
{
    g_last_error.clear();
    if (out_inferred) out_inferred->is_set = 0;

    if (!g_init_ok)
        return fail("[init]", func_name, "decompiler library not initialised");
    if (!bytes || len == 0)
        return fail("[init]", func_name, "null/empty byte buffer");

    // Work on a local mutable copy so a tail-call rewrite (if any) never
    // touches the caller's buffer.
    std::vector<uint8_t> work(bytes, bytes + len);
    bool tail_call_rewritten =
        rewrite_tail_call(work, real_func_addr, sigs, sig_count);
    if (tail_call_rewritten) {
        LOGI_B("[S0.5] rewrote trailing tail-call B->BL+RET for %s", func_name);
    }

    // ------------------------------------------------------------------
    // Stage 1 — write raw bytes to a temp file for RawLoadImage
    // ------------------------------------------------------------------
    LOGI_B("[S1] writing %zu bytes to %s for %s", work.size(), tmp_path, func_name);
    {
        std::ofstream f(tmp_path, std::ios::binary | std::ios::trunc);
        if (!f) return fail("[S1:write_temp]", func_name, tmp_path);
        f.write(reinterpret_cast<const char*>(work.data()), (std::streamsize)work.size());
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

        // Range check (use work.size(): a tail-call rewrite may have
        // appended a synthetic RET that must be included in the range).
        uintb highest = ram->getHighest();
        if ((uintb)real_func_addr > highest ||
            (work.size() > 0 && (uintb)(real_func_addr + work.size() - 1) > highest)) {
            delete arch; std::remove(tmp_path);
            std::ostringstream oss;
            oss << "function range [0x" << std::hex << real_func_addr
                << ", 0x" << (real_func_addr + work.size() - 1)
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
        // Stage 2.5b — comprehensive ELF symbol / data-label injection
        //
        // Inject ALL known ELF symbols (functions and data objects) into
        // Ghidra's global scope so the decompiler emits real names directly
        // instead of generating FUN_addr / DAT_addr auto-names.
        //
        // This is the r2ghidra-style approach: pre-populate the scope with
        // the full symbol table rather than text-rewriting the output.
        //
        // - Function symbols  → scope->addFunction  (creates FunctionSymbol)
        // - Data/label symbols → scope->addCodeLabel (creates LabSymbol)
        //
        // Errors are non-fatal; a collision or invalid address is caught and
        // skipped — the worst outcome is Ghidra falls back to its auto-name
        // for that address, same as before.
        // ------------------------------------------------------------------
        if (dsyms && dsym_count > 0) {
            LOGI_B("[S2.5b] injecting %zu ELF labels for %s",
                   dsym_count, func_name);
            Scope* lscope = arch->symboltab->getGlobalScope();
            size_t dsym_ok = 0;
            for (size_t i = 0; i < dsym_count; ++i) {
                const PeekDataSym& ds = dsyms[i];
                if (!ds.name || ds.name[0] == '\0' || ds.address == 0) continue;
                if (ds.address == real_func_addr) continue;
                Address dsAddr(ram, (uintb)ds.address);
                try {
                    if (ds.is_func)
                        lscope->addFunction(dsAddr, ds.name);
                    else
                        lscope->addCodeLabel(dsAddr, ds.name);
                    ++dsym_ok;
                } catch (...) {
                    // Collision with an existing symbol or out-of-range
                    // address — skip silently.
                }
            }
            LOGI_B("[S2.5b] injected %zu/%zu ELF labels for %s",
                   dsym_ok, dsym_count, func_name);
        }

        // ------------------------------------------------------------------
        // Stage 3 — register target function symbol + followFlow
        // ------------------------------------------------------------------
        LOGI_B("[S3] addFunction + followFlow for %s (addr=0x%llx len=%zu work=%zu)",
               func_name, (unsigned long long)real_func_addr, len, work.size());
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
            Address eaddr(ram, (uintb)(real_func_addr + work.size() - 1));
            LOGI_B("[S3] followFlow baddr=0x%llx eaddr=0x%llx for %s",
                   (unsigned long long)real_func_addr,
                   (unsigned long long)(real_func_addr + work.size() - 1),
                   func_name);
            fd->followFlow(baddr, eaddr);
            LOGI_B("[S3] followFlow OK for %s", func_name);

            // ----------------------------------------------------------------
            // Stage 3.5 — minimal self-prototype fallback
            //
            // inject_sig() (Stage 2.5) only locks an output type for callees
            // that appear in sigs[] with real return-type info. The target
            // function itself is deliberately excluded from that list by the
            // caller (peek_jni.cpp skips self when building c_sigs), so by
            // default fd has no output lock at all here.
            //
            // Without a lock, ActionDeadCode is free to eliminate the value
            // (and the instruction that produced it) flowing into this
            // function's own RETURN if nothing else in this isolated,
            // single-function decompile consumes it — which is exactly what
            // happens for a function whose entire body is "read a system
            // register, return it" (no other use exists to anchor on), or
            // for a function whose real return value, on its very first
            // decompile, comes from a sibling call that hasn't been learned
            // yet. The result is a function that decompiles "successfully"
            // but with an empty body and no return statement.
            //
            // We must NOT apply this unconditionally though — a genuinely
            // void function (e.g. an exported stub with an empty body) would
            // start "returning" whatever garbage happens to sit in X0 if we
            // blindly forced a non-void lock on every function. So before
            // locking anything, check whether this function's own raw
            // p-code (right after followFlow, before any pipeline action
            // has run) ever actually writes to the model's output storage
            // location at all. If it never does, this is consistent with a
            // real void function and we leave it alone, same as before this
            // fix existed.
            // ----------------------------------------------------------------
            bool self_sig_supplied = false;
            if (sigs) {
                for (size_t i = 0; i < sig_count; ++i) {
                    if (sigs[i].address == real_func_addr) { self_sig_supplied = true; break; }
                }
            }
            if (!self_sig_supplied && !fd->getFuncProto().isOutputLocked()) {
                try {
                    // Resolve where this model's calling convention puts an
                    // 8-byte return value (X0 on AAPCS64) without hand-coding
                    // any register address ourselves.
                    PrototypePieces probe;
                    probe.model           = arch->defaultfp;
                    probe.name            = func_name;
                    probe.firstVarArgSlot = -1;
                    probe.outtype         = arch->types->getBase(8, TYPE_UNKNOWN);
                    std::vector<ParameterPieces> resolved;
                    arch->defaultfp->assignParameterStorage(probe, resolved, true);

                    // assignParameterStorage's first entry is conventionally
                    // the return value's storage.
                    bool wrote_to_output = false;
                    if (!resolved.empty() && !resolved[0].addr.isInvalid()) {
                        const Address& outAddr = resolved[0].addr;
                        int4 outSize = resolved[0].type ? resolved[0].type->getSize() : 8;
                        for (auto iter = fd->beginOpAlive(); iter != fd->endOpAlive(); ++iter) {
                            PcodeOp* op = *iter;
                            Varnode* outvn = op->getOut();
                            if (!outvn) continue;
                            if (outvn->getAddr().overlap(0, outAddr, outSize) != -1) {
                                wrote_to_output = true;
                                break;
                            }
                        }
                    }

                    if (wrote_to_output) {
                        PrototypePieces proto;
                        proto.model           = arch->defaultfp;
                        proto.name            = func_name;
                        proto.firstVarArgSlot = -1;
                        // Generic 8-byte "unknown" — wide enough to cover the
                        // X0 return register without asserting a specific C
                        // type we have no evidence for. Real metadata/stdlib
                        // signatures (handled in Stage 2.5) always take
                        // precedence over this fallback.
                        proto.outtype = arch->types->getBase(8, TYPE_UNKNOWN);
                        fd->getFuncProto().setPieces(proto);
                        fd->getFuncProto().setOutputLock(true);
                        LOGI_B("[S3.5] applied minimal self-output lock for %s "
                               "(output storage was written)", func_name);
                    } else {
                        LOGI_B("[S3.5] skipped self-output lock for %s "
                               "(output storage never written — consistent with void)",
                               func_name);
                    }
                } catch (...) {
                    // Non-fatal: fall through with whatever the pipeline
                    // infers on its own, same as before this fix existed.
                }
            }
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
// V2 — wrapper around V3 with zero data syms (ABI compatibility)
// ---------------------------------------------------------------------------

char* peek_decompile_bytes_v2(const uint8_t* bytes, size_t len,
                               const char*    func_name,
                               const char*    tmp_path,
                               uint64_t       real_func_addr,
                               const PeekFuncSig* sigs,
                               size_t         sig_count,
                               PeekInferredSig*   out_inferred)
{
    return peek_decompile_bytes_v3(bytes, len, func_name, tmp_path,
                                   real_func_addr,
                                   sigs, sig_count,
                                   nullptr, 0,
                                   out_inferred);
}

// ---------------------------------------------------------------------------
// V1 — backwards-compatible wrapper
// ---------------------------------------------------------------------------

char* peek_decompile_bytes(const uint8_t* bytes, size_t len,
                            const char* func_name, const char* tmp_path,
                            uint64_t real_func_addr)
{
    return peek_decompile_bytes_v3(bytes, len, func_name, tmp_path,
                                   real_func_addr,
                                   nullptr, 0,
                                   nullptr, 0,
                                   nullptr);
}

void peek_decompiler_shutdown(void) {
    if (g_init_ok) {
        SleighArchitecture::shutdown();
        g_init_ok = false;
    }
}

} // extern "C"
