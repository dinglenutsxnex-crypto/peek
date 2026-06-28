---
name: Pseudocode pass pipeline
description: The ordered post-processing passes applied after Ghidra decompiles a function, plus the cache tag rule.
---

## Pass order (nativeDecompileFunction in peek_jni.cpp)

0. `resolve_ghidra_tokens(result, elf)` — replaces Ghidra auto-names (FUN_, DAT_, PTR_FUN_, thunk_FUN_, LAB_, EXTR_, func_0x<hex>, unk_<hex>) with real ELF symbol names or IDA-style `sub_ADDR` / `unk_addr`.
1. `jni_annotate(fn.name, result)` — JNI signature fixing, vtable resolution, JNI constant names. Contains sub-passes U0a/U0b/U0b2/U0b3/U0c/U1/U2 and JNI-specific J1–J6.
2. `resolve_data_refs(result, elf)` — converts `*Ram<hex16>` tokens (all prefix lengths: xRam, pRam, pcRam, puRam, plRam, pbRam, psRam, paRam, etc.) to string literals or symbol names; annotates JNI FindClass/GetMethodID string args.
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
- U0c4: `normalize_plus_neg` — `val + -1` → `val - 1`, `ptr + -0x18` → `ptr - 0x18` (Ghidra always emits addition of a negative literal instead of subtraction).
- U0b2 also now handles: `unaff_x29` → `frame_ptr`, `unaff_x30` → `link_reg`, `extraout_x0/x1` → `ret0/ret1`, `BADSPACEBASE` → `sp`, `register0x00000008` → `x8_reg`.
- U0c: `resolve_ghidra_pseudoops` — CONCAT/CARRY/SCARRY/SBORROW/SUB expansions.
- U1: `strip_stack_canary` — remove tpidr_el0 / canary boilerplate.
- U2: `rename_return_var` — rename sole return accumulator to `ret`.
- U2b: `collapse_atomic_refcount` — collapses the ARM64 LDXR/STXR exclusive-monitor std::string refcount pattern. Detects `if (pthread_create == 0) { ... } else { do { ExclusiveMonitorPass ... } while (...); }` (~100 occurrences per file) and replaces with just the simple branch body at one less indent level.
- U3–U6: write-only var removal, dead-init removal, implicit return fix, generic var rename.
- JNI-specific (J1–J6): signature fix, param renames, vtable calls, JNI constants, local type inference, RegisterNatives collapse.

## resolve_ghidra_tokens token table (peek_jni.cpp kTokens)

Order: thunk_FUN_ (10) > PTR_FUN_ (8) > FUN_ (4) > DAT_ (4) > LAB_ (4) > EXTR_ (5) > func_0x (7) > unk_ (4).
- `func_0x<hex>` — Ghidra lowercase function variant (Unity/NDK stripped); → sym_map or sub_ADDR.
- `unk_<hex>` — direct Ghidra data token; → C-string or sym_map or kept as unk_ADDR.

## resolve_data_refs *Ram prefix matching (peek_jni.cpp)

The walk-back loop at the "Ram" search in Pass 1 now consumes **all** lowercase letters before "Ram", not just one. This handles both single-char (xRam, pRam) and multi-char (pcRam, puRam, plRam, pbRam, psRam, paRam) Ghidra type prefixes uniformly.

## Cache tag rule

**Why:** The DB caches pseudocode per function. Any pass change produces different output. `JNI_ANNOTATOR_CACHE_TAG` (in `jni_annotator.cpp`, referenced in `peek_jni.cpp`) is prepended; a mismatch triggers auto re-decompilation.

**How to apply:** Bump the tag whenever any pass changes output. Current tag: `"\x01PEEK_ANN_V24\x01\n"`.

**Important:** Brace-counting scripts must be string/char-aware — the tag contains `\x01` escapes.

## kStdlibProtos (peek_jni.cpp)

~530+ entries covering C stdlib, C++ runtime, libstdc++/libc++ std::string/vector/mutex/thread, Android NDK (ALooper, ANativeWindow, AAsset, AInputEvent), il2cpp Unity codegen helpers.
