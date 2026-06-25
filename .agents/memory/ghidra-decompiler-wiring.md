---
name: Ghidra decompiler wiring
description: Architectural decisions for plumbing the Ghidra standalone decompiler into peek_native.so on Android
---

## ABI isolation — decompiler_bridge pattern
`decompiler_core` requires C++ exceptions and RTTI; `peek_native`'s other TUs use `-fno-exceptions -fno-rtti`. The fix: a thin `decompiler_bridge.cpp` compiled with `-fexceptions -frtti` (set via `set_source_files_properties` in CMakeLists so the later flag wins over the target-wide `-fno-exceptions`). It exposes only a plain-C interface (`decompiler_bridge.h`) that `peek_jni.cpp` calls — no C++ types cross the boundary.

**Why:** mixing exception ABIs in the same `.so` causes undefined behaviour at link time or runtime. The bridge isolates the RTTI/exception "island".

**How to apply:** any future C++ code that includes Ghidra headers must live in `decompiler_bridge.cpp` (or a similarly flagged file). Never include `libdecomp.hh`/`raw_arch.hh` from a `-fno-exceptions` TU.

## startDecompilerLibrary — once per process
`startDecompilerLibrary(vector<string> specDirs)` (from `libdecomp.hh`) populates the global `SleighArchitecture::specpaths` and must be called exactly once. Guarded by `std::call_once`. Called from `nativeInitDecompiler` (JNI), which Kotlin calls once in `MainActivity.onCreate` on an IO coroutine.

`SleighArchitecture::shutdown()` is called only at process exit (or never on Android — the process dies cleanly).

## Per-function pipeline
Each `nativeDecompileFunction` call:
1. Checks `functions.pseudocode` DB column (cache hit → return immediately).
2. Re-parses the ELF from `ctx->file_path` (AnalysisContext doesn't keep ELF data in RAM).
3. Extracts function bytes via `va_to_ptr` (executable sections only).
4. Writes bytes to `filesDir/decomp_<funcId>.bin` (unique per func, cleaned up after).
5. `new RawBinaryArchitecture` → set `adjustvma = real_func_addr` → `init` → `addFunction(Address(ram, real_func_addr))` → `followFlow(baddr, eaddr)` → `allacts.perform` → `print->docFunction` → `delete arch`.
6. Stores result in `functions.pseudocode` and returns.

## CRITICAL: RawLoadImage::adjustVma null-deref bug (SIGSEGV at 0x64)
Setting `arch->adjustvma` (non-zero) causes `buildLoader()` to call `ldr->adjustVma()`.
Inside `adjustVma()`, `spaceid->getWordSize()` is called — but `spaceid` is **null** at that point.
`spaceid` is only set later via `attachToSpace()` in `postSpecFile()`.
`wordsize` is at offset **0x64** in `AddrSpace`, so `nullptr->wordsize` → SIGSEGV at 0x64.

**Fix:** `loadimage.cc RawLoadImage::adjustVma()` — guard: `uint4 ws = spaceid ? spaceid->getWordSize() : 1;`
For AArch64 wordsize==1 anyway, so this is always correct. Do NOT remove this guard.

## SLEIGH spec assets
Four files extracted from Android assets to `filesDir/decompiler_spec/` on first launch:
- `AARCH64.sla` (pre-compiled sleigh spec, ~2 MB)
- `AARCH64.ldefs` (language definitions, references `slafile="AARCH64.sla"`)
- `AARCH64.pspec` (processor spec)
- `AARCH64.cspec` (calling convention)

The spec dir path is passed to `startDecompilerLibrary` via `nativeInitDecompiler(specDir)`.

## DB schema
`functions` table gained a nullable `pseudocode TEXT` column. Migration via `ALTER TABLE ... ADD COLUMN` in `create_schema()` (silently ignored on new DBs). New DB methods: `get_pseudocode(func_id)`, `store_pseudocode(func_id, code)`, `get_function_by_id(func_id)`.

## UI tab
`TabId.PSEUDOCODE` ("DECOMP") added as second tab (after ASM). `PseudocodeFragment` observes `AnalysisViewModel.selectedFunction`, launches a coroutine on `Dispatchers.IO`, shows a spinner while decompiling, displays result in a selectable monospace `TextView` with a copy button.
