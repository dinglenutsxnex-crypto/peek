# Project: ARM64 .so Analyzer for Android — v1, built from scratch

## What this is
A new, minimal Android app for static analysis of ARM64 (.so) shared library
files, inspired by IDA Pro's listing view. This is a FRESH repository — do not
fork or build on top of any existing app. No decompiler, no Python scripting in
this iteration. Keep scope tight.

## Why "from scratch" matters here
We looked at https://github.com/yhs0602/Android-Disassembler as a reference.
It is 81% Kotlin, 13% Java, only ~5% C++, and pulls in a long tail of unrelated
dependencies (PE/DLL parsing, .NET decompiling, dex/smali support, color
pickers, storage choosers, multi-level list views) that have nothing to do with
ARM64 .so analysis. That breadth causes Dependabot noise and build fragility
that has nothing to do with our actual feature set.

**Use that repo only as a reference for two specific things:**
1. How they structured the Capstone JNI wrapper (their `capstone`/`capstone2`
   directories) — read it for the calling pattern (how raw bytes get handed to
   Capstone's `cs_disasm` and how results cross the JNI boundary), then write
   our own clean version updated against Capstone's current release rather than
   copying their files outright. Check Capstone's latest release on GitHub
   (https://github.com/capstone-engine/capstone/releases) and use that version's
   API, since the old repo's integration predates several Capstone releases.
2. Their xref approach is referenced from a Stack Exchange answer, not a mature
   built-in feature — don't copy it; we're building xref detection ourselves
   per the spec below.

Do not vendor their Gradle setup, their submodules, their other parser
dependencies, or any unrelated code. This is a clean repo with a short,
deliberate dependency list.

## Tech split (deliberate, do not deviate)
- **C++**: ELF parsing, ARM64 disassembly (Capstone), xref detection, all
  SQLite read/write. This is where all binary-analysis logic lives, compiled
  to a single `.so` via CMake/NDK.
- **Kotlin**: the entire UI layer — Activities, RecyclerViews for the listing
  view and function list, file picker (SAF), permissions, navigation between
  views. Kotlin calls into the native library via JNI and renders whatever
  comes back. Kotlin should contain no parsing or disassembly logic of its own
  — it's a thin, well-built UI shell, not a thin afterthought.

## Core requirement: native library does the work
ELF parsing, disassembly, xref computation, and SQLite caching all happen in
C++, exposed to Kotlin via a small, clear JNI interface (e.g.
`openBinary(path) -> handle`, `getFunctionList(handle) -> List<FunctionInfo>`,
`getInstructions(handle, funcAddr) -> List<InstructionInfo>`,
`getXrefs(handle, address) -> List<XrefInfo>`). Define this JNI contract
explicitly and document it in a README or header comment — don't let it grow
ad hoc.

## What to build in this iteration

### 1. ELF parsing (C++)
Parse ARM64 .so files: sections, segments, symbol tables (.dynsym/.symtab),
dynamic relocations, import/export symbols. Use a lightweight ELF parsing
approach — either a minimal hand-rolled parser scoped to ELF64/ARM64 only
(preferred, keeps dependencies minimal since we don't need multi-arch/PE/etc
support) or a small vendored single-purpose ELF library if one is clearly
better suited and lightweight. Do not pull in a parser designed for many
formats (PE, Mach-O, etc.) — ARM64 ELF only.

### 2. Disassembly (C++, via Capstone)
Vendor Capstone fresh from its current GitHub release (check
https://github.com/capstone-engine/capstone/releases for the latest stable
tag), built via CMake for `arm64-v8a` ABI only (no need to build Capstone's
other architecture backends — disable them in the CMake config to keep build
size/time down). Write a clean JNI wrapper around `cs_disasm` scoped to what
we actually need: address, byte length, raw bytes (hex), mnemonic, operands
per instruction.

### 3. SQLite-backed analysis cache (C++)
Use the sqlite3 C API directly (no ORM, no ROOM). On first analysis of a
binary, persist results so reopening loads from cache instead of
re-disassembling.

Minimum schema:
- `binaries`: file_hash (SHA256, used as cache key), file_path, last_analyzed_timestamp
- `functions`: address, size, name (if symbol exists), end_address, binary_id (FK)
- `instructions`: address, size, bytes (hex), mnemonic, operands, function_id (FK)
- `symbols`: address, name, type (import/export), is_import (bool), binary_id (FK)
- `xrefs`: from_address, to_address, ref_type (call/jump/data), binary_id (FK)

Use SHA256 of the file (not its path) as the cache key, so a renamed/moved
copy of the same binary still hits the cache. Compute the hash in C++.

### 4. Basic xref detection (C++)
While disassembling, detect:
- Direct calls/branches (BL, B, B.cond, CBZ, CBNZ, TBZ, TBNZ, etc.) → code-to-code xrefs
- ADRP+LDR / ADRP+ADD pairs referencing data sections → code-to-data xrefs
Store in the `xrefs` table. Skip indirect/computed branch resolution for now —
direct xrefs only in this iteration.

### 5. Kotlin UI
- Listing view: RecyclerView showing offset / bytes / mnemonic / operands per
  instruction for the function/range in view, loaded from the native layer
  (which queries SQLite, not an in-memory dump of the whole binary)
- Function list view: RecyclerView of address + name from the `functions`
  table, tap to jump to that function's disassembly
- Basic xref display: when viewing a function, show calls-from/called-by
  pulled from the `xrefs` table
- File picker using SAF (Storage Access Framework) to select a `.so` file
- Simple, clean visual style — doesn't need to be fancy in v1, just functional
  and not broken

## Explicitly OUT of scope for this iteration:
- Decompiler / pseudocode generation (no Ghidra, no SLEIGH, no p-code)
- Python scripting or any scripting engine (no Chaquopy yet)
- Code/pseudocode dump-to-zip export
- Indirect/computed branch xref resolution
- Multi-architecture support (x86, MIPS, etc.) — ARM64 only
- PE/Mach-O/dex or any non-ELF format support
- Any cloud/server component — fully on-device

## Build & CI requirement
Must build via GitHub Actions from a clean state:
- `.github/workflows/build.yml` checking out the repo (no submodules needed
  if Capstone is vendored directly as source rather than a submodule —
  prefer vendoring source directly to avoid submodule-init friction)
- JDK + Android SDK + NDK setup (pin specific, current NDK version explicitly
  — don't float on "latest" to avoid silent breakage)
- `./gradlew assembleDebug`
- Upload resulting APK as a build artifact
- Keep CI minutes lean: this should be a small, fast build given the
  deliberately short dependency list — if the build is slow or pulls in a lot
  of unrelated packages, that's a signal something's been added that
  shouldn't be in scope

Set up Dependabot config (or explicitly disable it / scope it narrowly to just
our direct dependencies) so it isn't generating noise — we control our
dependency list tightly on purpose, so Dependabot churn should be minimal by
construction.

## Target constraints
- Low-end device target: 4GB RAM (~2GB free at runtime), 64GB storage
  (~10GB free)
- Query SQLite for the visible function/range as needed rather than holding
  full-binary instruction lists in memory (Kotlin side especially — it should
  never hold more than what's needed for the current view)

## Deliverable
A new, clean repo that: opens a .so file via SAF, parses ELF and disassembles
ARM64 code via a freshly-vendored current Capstone release (C++, JNI), detects
basic direct xrefs, caches everything in SQLite via C++, displays it in a
Kotlin RecyclerView-based listing + function list UI, and builds a debug APK
successfully via a lean GitHub Actions workflow with minimal/no Dependabot
noise.
