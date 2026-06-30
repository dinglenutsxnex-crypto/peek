---
name: Ghidra decompiler wiring
description: Architectural decisions for plumbing the Ghidra standalone decompiler into peek_native.so on Android
---

## ABI isolation — decompiler_bridge pattern
`decompiler_core` requires C++ exceptions and RTTI; `peek_native`'s other TUs use `-fno-exceptions -fno-rtti`. The fix: files wrapping Ghidra headers are compiled with `-fexceptions -frtti` (set via `set_source_files_properties` — the per-file flag wins over the target-wide default).

Affected files: `peek_load_image.cpp`, `peek_scope.cpp`, `peek_architecture.cpp`, `decompiler_bridge.cpp`.

**Why:** mixing exception ABIs in the same `.so` causes undefined behaviour. The bridge isolates the RTTI/exception "island".

**How to apply:** any future C++ code that includes Ghidra headers must live in one of these flagged files. Never include `libdecomp.hh` / Ghidra `*.hh` from a `-fno-exceptions` TU.

## r2ghidra-mirrored scope architecture (PeekScope / PeekArchitecture)
The decompiler now uses a **PeekArchitecture : SleighArchitecture** approach that exactly mirrors r2ghidra's R2Architecture/R2Scope pattern. The three new files are:

- **`peek_load_image.h/cpp`** — `PeekLoadImage : LoadImage`; serves the full ELF VA space from `ElfParseResult::data` plus an optional patch overlay for tail-call rewrites. No temp file.
- **`peek_scope.h/cpp`** — `PeekScope : Scope`; on-demand lazy symbol resolution from ELF; backed by a `ScopeInternal` cache. `addSymbolInternal`/`addMapInternal` throw (like R2Scope). External callers use `preRegisterFunction(addr, name)` to write into the cache directly.
- **`peek_architecture.h/cpp`** — `PeekArchitecture : SleighArchitecture`; overrides `buildLoader` (installs PeekLoadImage, applying any pre-set patch), `buildDatabase` (installs PeekScope as global scope), and `buildCoreTypes` (stdint names: uint8_t/uint32_t etc.).

**Why PeekScope instead of ScopeInternal pre-population:**
- Pre-populating ALL ELF symbols before init was Stage 2.5b (the broken approach). It called `scope->addFunction` on a `ScopeInternal` global scope, which DOES work for vanilla `ScopeInternal` but prevents the decompiler's own flow analysis from cleanly resolving cross-function call targets because names are locked before typing occurs.
- R2Scope/PeekScope let the decompiler query symbols on-demand as it encounters addresses, which is the architecturally correct way. The on-demand path calls `queryElfAbsolute(addr)` → `cache_->addFunction(addr, name)` or `cache_->addSymbol(...)`.

**How to use:**
- `preRegisterFunction(addr, name)` is the only "write" path for external code. Use it for: (a) injecting callee signatures (Stage 2.5), (b) registering the target function before `followFlow`.
- Do NOT call `scope->addFunction` or `scope->addCodeLabel` directly — those throw on PeekScope.
- `arch->setPatch(bytes, addr, len)` must be called BEFORE `arch->init(store)` — buildLoader reads it when constructing PeekLoadImage.

## startDecompilerLibrary — once per process
`startDecompilerLibrary(vector<string> specDirs)` (from `libdecomp.hh`) populates the global `SleighArchitecture::specpaths` and must be called exactly once. Guarded by `std::call_once`. Called from `nativeInitDecompiler` (JNI), which Kotlin calls once in `MainActivity.onCreate` on an IO coroutine.

## Per-function pipeline
Each `nativeDecompileFunction` call (in `peek_jni.cpp`):
1. Checks `functions.pseudocode` DB column (cache hit → return immediately).
2. Re-parses the ELF from `ctx->file_path`.
3. Validates `va_to_ptr` (executable section membership check + diagnostic logging).
4. Builds `c_sigs[]` (typed callee signatures from `ctx->sig_cache`, excluding self).
5. Calls `peek_decompile_elf(elf, name, addr, len, sigs, sig_count, &inferred)`.
6. Stores result in `functions.pseudocode` and returns.

Inside `peek_decompile_elf` (decompiler_bridge.cpp):
- S0.5: optional tail-call rewrite (B→BL+RET, stored as patch overlay).
- S2: `new PeekArchitecture(elf, errs)` → `setPatch(...)` → `arch->init(store)`.
- S2.5: inject callee sigs via `peekScope->preRegisterFunction` + lock prototype.
- S3: `preRegisterFunction(funcAddr, name)` → `followFlow(baddr, eaddr)`.
- S3.5: self-output lock fallback (checks p-code for writes to return register).
- S4: `allacts.perform(*fd)` → extract inferred sig.
- S5: `print->docFunction(fd)` → return malloc'd C string.

## CRITICAL: loadimage.cc null-deref bug (SIGSEGV at 0x64)
Applies if `adjustVma` is ever called on `RawLoadImage` when `spaceid` is null.
`spaceid` is only set via `attachToSpace()` in `postSpecFile()`.
`wordsize` is at offset 0x64 in `AddrSpace`, so `nullptr->wordsize` → SIGSEGV at 0x64.

**Fix:** `loadimage.cc RawLoadImage::adjustVma()` — guard: `uint4 ws = (spaceid != (AddrSpace *)0) ? spaceid->getWordSize() : 1;`

**Applied via sed in CI** (`.github/workflows/build.yml`) and `scripts/fetch_ghidra_decomp.sh`.

Note: with PeekArchitecture, we never use `RawBinaryArchitecture` or call `adjustVma` ourselves. The sed patch remains in CI as a safety net for the compiled-in Ghidra code.

## raw_arch.hh adjustvma visibility patch
The sed patch that makes `adjustvma` public in `raw_arch.hh` is still in CI but is no longer needed since we don't use `RawBinaryArchitecture`. Harmless to leave.

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
