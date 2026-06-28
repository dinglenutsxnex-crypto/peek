---
name: Pseudocode pass pipeline
description: The ordered post-processing passes applied after Ghidra decompiles a function, plus the cache tag rule.
---

## Pass order (nativeDecompileFunction in peek_jni.cpp)

0. `resolve_ghidra_tokens(result, elf)` — replaces Ghidra auto-names (FUN_XXXXXXXX, DAT_XXXXXXXX, PTR_FUN_, thunk_FUN_, LAB_, EXTR_) with real ELF symbol names or IDA-style `sub_ADDR` / `unk_addr`.
1. `jni_annotate(fn.name, result)` — JNI signature fixing, vtable resolution, JNI constant names. Contains its own sub-passes U0a/U0b/U0c/U1/U2 and JNI-specific J1–J6.
2. `resolve_data_refs(result, elf)` — converts `*Ram<hex16>` tokens to string literals or symbol names; annotates JNI FindClass/GetMethodID string args.
3. `annotate_algorithms(result)` — prepends crypto/obfuscation detection comments.

## Sub-passes inside jni_annotate (jni_annotator.cpp)

- U0a: Strip `/* WARNING: */` Ghidra warning comments.
- U0b: `resolve_xunknown_types` — xunknown1/2/4/8 → uint8_t/16/32/64.
- U0c: `resolve_ghidra_pseudoops` — CONCAT<A><B>→bit-shift, CARRY<N>→add-carry, SCARRY<N>→__OFADD__, SBORROW<N>→__OFSUB__, SUB<N>→(x-y).
- U1: `strip_stack_canary` — remove tpidr_el0 / canary boilerplate.
- U2: `rename_return_var` — rename sole return accumulator to `ret`.
- U3: `remove_writeonly_vars` — merge write-only vars into survivors.
- U4: `remove_dead_inits` — remove immediately-overwritten constant assignments.
- U5: `fix_implicit_return` — bare `return;` → `return <var>;` for jint functions.
- U6: `rename_generic_vars` — iVarN/xVarN/uVarN → ptr/f/val/v with numbering.
- JNI-specific (J1–J6): signature fix, param renames, vtable calls, JNI constants, local type inference, RegisterNatives collapse.

## Cache tag rule

**Why:** The DB caches pseudocode per function. Adding or changing any pass produces different output that won't be stored until old cache entries are evicted. The tag `JNI_ANNOTATOR_CACHE_TAG` (defined in `jni_annotator.cpp`, referenced in `peek_jni.cpp`) is prepended to stored pseudocode; a version mismatch triggers re-decompilation automatically.

**How to apply:** Any time a new pass is added or an existing pass is changed in a way that affects output, bump the version tag (e.g., V19 → V20). Current tag: `"\x01PEEK_ANN_V20\x01\n"`.

**Important:** Simple Python brace-counting scripts will give a wrong depth if they don't skip string literals — the tag string contains `\x01` and other escapes. Always use a comment/string/char-aware parser to verify balance.

## kStdlibProtos (peek_jni.cpp)

Large table of mangled/unmangled symbol → (return_type, param_count, params_csv) entries used for signature inference. Covers: C stdlib, ctype, time, files/dirs, memory mapping, dlopen/dlsym, networking, signals, pthread, semaphore, C++ runtime (__cxa_*, __gxx_*, _Unwind_*), libstdc++ std::string (old ABI + __cxx11), libc++ std::string + string_view + vector + mutex + thread + exception, Android NDK (ALooper, ANativeWindow, AAsset, AInputEvent). ~530+ entries as of V20.
