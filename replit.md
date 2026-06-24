# PEEK — ARM64 .so Analyzer for Android

## Overview
A clean, minimal Android app for static analysis of ARM64 ELF shared libraries.  
Package: `com.nex.peek` | minSdk: 26 | targetSdk: 34 | ABI: arm64-v8a only

## Tech stack
- **Kotlin** — UI layer only (Activities, RecyclerViews, SAF file picker, JNI bridge)
- **C++ (NDK r27c)** — ELF parsing, ARM64 disassembly (Capstone 5.0.1), xref detection, all SQLite I/O
- **CMake 3.22.1** — native build; fetches Capstone + SQLite at configure time via FetchContent
- **Gradle 8.7 / AGP 8.3.2 / Kotlin 1.9.23**

## Important: this is a pure Android project
There is no web server and no Replit preview. Development flow:
1. Edit code here in Replit
2. Push to GitHub
3. GitHub Actions (`.github/workflows/build.yml`) builds the debug APK automatically

## Building locally
```bash
# Requires: JDK 17, Android SDK, NDK 27.2.12479018, CMake 3.22.1
gradle wrapper --gradle-version 8.7   # one-time: generates gradle/wrapper/gradle-wrapper.jar
chmod +x gradlew
./gradlew assembleDebug
```
The first build downloads Capstone 5.0.1 and SQLite 3.46.1 via CMake FetchContent — expect ~2-3 min.

## Key files
| File | Purpose |
|------|---------|
| `app/src/main/cpp/CMakeLists.txt` | Native build; FetchContent for Capstone + SQLite |
| `app/src/main/cpp/peek_jni.cpp` | JNI bridge — all native↔Kotlin contracts |
| `app/src/main/cpp/elf_parser.cpp` | Hand-rolled ELF64/ARM64 parser |
| `app/src/main/cpp/disassembler.cpp` | Capstone 5.x ARM64 disassembler wrapper |
| `app/src/main/cpp/xref_detector.cpp` | Direct call/branch/data xref detection |
| `app/src/main/cpp/db_cache.cpp` | SQLite analysis cache (SHA256 cache key) |
| `app/src/main/java/com/nex/peek/PeekNative.kt` | Typed Kotlin facade over JNI |
| `.github/workflows/build.yml` | CI — pinned NDK r27c, uploads APK artifact |

## User preferences
- Package name: `com.nex.peek`
- App name: PEEK
- App icon: eye SVG (grey iris, white sclera, black pupil, white catchlight)
- ARM64 only — no multi-arch, no PE/Mach-O/dex, no decompiler
- Dependencies kept minimal and deliberate
