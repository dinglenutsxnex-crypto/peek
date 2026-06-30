---
name: Pseudocode pass pipeline
description: The ordered post-processing passes applied after Ghidra decompiles a function, plus the cache tag rule.
---

## Pass order (nativeDecompileFunction in peek_jni.cpp)

**Stage 2.5b (in decompiler_bridge.cpp — BEFORE decompilation):**
`peek_decompile_bytes_v3` now accepts `dsyms`/`dsym_count` (a `PeekDataSym[]` of all ELF symbols). Before `followFlow`, ALL ELF symbols (functions + data objects) are injected into Ghidra's global scope via `scope->addFunction` and `scope->addCodeLabel`. This is the r2ghidra-style approach: the decompiler itself emits real names instead of auto-generating `FUN_addr`/`DAT_addr` tokens. The old `resolve_ghidra_tokens` text-rewriting pass (which matched FUN_/DAT_/PTR_FUN_/thunk_FUN_/LAB_/EXTR_/func_0x/unk_ tokens and looked up addresses post-hoc) is **deleted** from peek_jni.cpp and replaced by this.

**Post-decompilation passes (peek_jni.cpp):**
1. `jni_annotate(fn.name, result)` — JNI signature fixing, vtable resolution, JNI constant names, AND all type-normalization sub-passes (U0b: xunknown types, U0b2: register params, U0b3: goto labels, U0c/U0c4: pseudoops/plus-neg, U1: stack canary, U2: return var rename, U2b/U2c: atomic collapse). Also: U3–U6, J1–J6. No-op for non-JNI functions except the normalization passes.
2. `resolve_data_refs(result, elf)` — converts any remaining `*Ram<hex16>` tokens (addresses with no ELF symbol) to string literals or symbol names; annotates JNI FindClass/GetMethodID string args.
3. `annotate_algorithms(result)` — prepends crypto/obfuscation detection comments.

## Sub-passes inside jni_annotate (jni_annotator.cpp)

- U0a: Strip `/* WARNING: */` Ghidra warning comments.
- U0b: `resolve_xunknown_types` — maps every Ghidra non-standard type to a C99 type:
  - `xunknown1/2/4/8` → uint8_t/16/32/64
  - `uint1/2/4/8`, `int1/2/4/8`, `uint16/32/64`, `int16/32/64` → standard _t forms
  - `undefined1/2/4/8`, `undefined` → uint8_t/16/32/64 / uint8_t
  - `ulonglong` → uint64_t, `longlong` → int64_t, `ulong` → uint32_t, `ushort` → uint16_t, `uchar` → uint8_t
  - Longer names always listed before shorter to prevent partial matches.
- U0b2: `resolve_register_params` — ARM64 register variable → readable name:
  - `in_x0..x7` / `in_w0..w7` → param1..param8
  - `in_d0..d7` / `in_s0..s7` → fparam1..fparam8
  - `in_q0..q7` / `in_v0..v7` → vparam1..vparam8 (SIMD 128-bit)
  - `in_x8` → ret_ptr, `in_x18` → tls_ptr
  - Processed longest-name-first (in_x18 before in_x1).
- U0b3: `resolve_goto_labels` — code_r0x<hex> → L_<hex>
- U0c4: `normalize_plus_neg` — `val + -1` → `val - 1`, `ptr + -0x18` → `ptr - 0x18`
- U0b2 also now handles: `unaff_x29` → `frame_ptr`, `unaff_x30` → `link_reg`, `extraout_x0/x1` → `ret0/ret1`, `BADSPACEBASE` → `sp`, `register0x00000008` → `x8_reg`.
- U0c: `resolve_ghidra_pseudoops` — CONCAT/CARRY/SCARRY/SBORROW/SUB expansions.
- U1: `strip_stack_canary` — remove tpidr_el0 / canary boilerplate.
- U2: `rename_return_var` — rename sole return accumulator to `ret`.
- U2b: `collapse_atomic_refcount` — collapses the ARM64 LDXR/STXR exclusive-monitor refcount pattern.
- U2c: `collapse_inverted_atomic` — handles the inverted form.
- U3–U6: write-only var removal, dead-init removal, implicit return fix, generic var rename.
- JNI-specific (J1–J6): signature fix, param renames, vtable calls, JNI constants, local type inference, RegisterNatives collapse.

## resolve_data_refs *Ram prefix matching (peek_jni.cpp)

The walk-back loop at the "Ram" search in Pass 2 now consumes **all** lowercase letters before "Ram", not just one. This handles both single-char (xRam, pRam) and multi-char (pcRam, puRam, plRam, pbRam, psRam, paRam) Ghidra type prefixes uniformly.

## Bridge API (decompiler_bridge.h)

- `PeekFuncSig` — typed function signature for Stage 2.5 injection (with return type + param types).
- `PeekDataSym` — ELF symbol record for Stage 2.5b injection (`{address, name, is_func}`).
- `peek_decompile_bytes_v3` — current primary API: takes both `sigs`/`sig_count` and `dsyms`/`dsym_count`.
- `peek_decompile_bytes_v2` — wrapper calling v3 with `nullptr, 0` for dsyms (ABI compat).
- `peek_decompile_bytes` — v1 wrapper (passes all nulls).

## Ghidra decompiler source

The `decompiler/` directory is **NOT committed** (gitignored). It is fetched from:
`https://github.com/NationalSecurityAgency/ghidra/archive/refs/tags/Ghidra_12.1.2_build.zip`
- CI: `.github/workflows/build.yml` downloads + extracts + applies adjustVma patch automatically.
- Local: run `./scripts/fetch_ghidra_decomp.sh` once before building.
- The adjustVma patch (sed on `loadimage.cc`) remains essential — see ghidra-decompiler-wiring.md.

## Cache tag rule

**Why:** The DB caches pseudocode per function. Any pass change produces different output. `JNI_ANNOTATOR_CACHE_TAG` (in `jni_annotator.cpp`, referenced in `peek_jni.cpp`) is prepended; a mismatch triggers auto re-decompilation.

**How to apply:** Bump the tag whenever any pass changes output. Current tag: `"\x01PEEK_ANN_V27\x01\n"`.

**Important:** Brace-counting scripts must be string/char-aware — the tag contains `\x01` escapes.

## kStdlibProtos (peek_jni.cpp)

~530+ entries covering C stdlib, C++ runtime, libstdc++/libc++ std::string/vector/mutex/thread, Android NDK (ALooper, ANativeWindow, AAsset, AInputEvent), il2cpp Unity codegen helpers.
