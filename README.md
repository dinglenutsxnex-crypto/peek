# PEEK — ARM64 .so Analyzer for Android

A minimal, on-device static analysis tool for ARM64 shared libraries (`.so` files).
Inspired by IDA Pro's listing view. No decompiler, no server, no bloat.

## What it does

1. **Open a `.so` file** via the Android Storage Access Framework (SAF file picker)
2. **Parse the ELF64/ARM64 binary** — sections, symbol tables, imports/exports
3. **Disassemble ARM64 machine code** via Capstone 5.x (built fresh from source via NDK)
4. **Detect direct xrefs** — BL/B/B.cond/CBZ/CBNZ/TBZ/TBNZ calls & branches, plus ADRP+ADD/LDR data references
5. **Cache everything in SQLite** — reopening the same binary loads instantly from cache
6. **Browse the results** in a clean RecyclerView UI: function list → disassembly listing → xref viewer

## Tech split

| Layer | What it does |
|-------|-------------|
| **C++ (NDK)** | ELF parsing, ARM64 disassembly (Capstone), xref detection, all SQLite read/write |
| **Kotlin** | Activities, RecyclerViews, SAF file picker, JNI calls, UI only — no parsing logic |

## JNI contract

Defined in `peek_jni.cpp` and mirrored in `PeekNative.kt`:

```
openBinary(path, dbDir) → Long handle
getFunctionList(handle) → List<FunctionInfo>
getInstructions(handle, funcId, limit, offset) → List<InstructionInfo>
getXrefs(handle, address) → List<XrefInfo>
getSymbols(handle) → List<SymbolInfo>
getInstructionCount(handle, funcId) → Long
closeBinary(handle)
```

## Dependencies

| Dep | How vendored | Version |
|-----|-------------|---------|
| Capstone | CMake `FetchContent` (source, arm64 only) | 5.0.1 |
| SQLite | CMake `FetchContent` (amalgamation) | 3.46.1 |
| AndroidX Core KTX | Gradle | 1.13.1 |
| AndroidX AppCompat | Gradle | 1.7.0 |
| Material Components | Gradle | 1.12.0 |
| RecyclerView | Gradle | 1.3.2 |

No PE/Mach-O/dex parsers. No decompiler backends. No scripting engine.
The dependency list is short on purpose — Dependabot churn is minimal by construction.

## Database schema

```sql
binaries     (id, file_hash SHA256, file_path, last_analyzed_timestamp)
functions    (id, binary_id, address, size, name, end_address)
instructions (id, function_id, address, size, bytes_hex, mnemonic, operands)
symbols      (id, binary_id, address, name, type_str, is_import)
xrefs        (id, binary_id, from_address, to_address, ref_type)
```

Cache key is SHA-256 of file content — a renamed/moved copy of the same binary still hits the cache.

## Build locally

Requirements: Android Studio Hedgehog+ or command-line tools, JDK 17, NDK r27c.

```bash
# Generate the Gradle wrapper JAR (one-time, if not present)
gradle wrapper --gradle-version 8.7

chmod +x gradlew
./gradlew assembleDebug
# APK: app/build/outputs/apk/debug/app-debug.apk
```

The NDK must be installed at `$ANDROID_SDK_ROOT/ndk/27.2.12479018` (or set `ANDROID_NDK_HOME`).
Capstone 5.0.1 and SQLite 3.46.1 are downloaded automatically by CMake during the first build.

## CI/CD

GitHub Actions (`.github/workflows/build.yml`) runs `assembleDebug` on every push/PR to `main`.
Pins NDK r27c (`27.2.12479018`) and CMake 3.22.1 explicitly to avoid silent breakage.
The debug APK is uploaded as a build artifact with 14-day retention.

## Scope (v1)

✅ ELF64/ARM64 parsing  
✅ ARM64 disassembly via Capstone 5.x  
✅ SQLite analysis cache  
✅ Direct xref detection (calls, branches, data refs)  
✅ Function list + disassembly listing + xref viewer  
✅ GitHub Actions CI + Dependabot config  

❌ Decompiler / pseudocode  
❌ Python scripting  
❌ Indirect/computed branch xref resolution  
❌ Multi-architecture (ARM32, x86, MIPS)  
❌ Non-ELF formats (PE, Mach-O, dex)  
❌ Cloud/server component  
