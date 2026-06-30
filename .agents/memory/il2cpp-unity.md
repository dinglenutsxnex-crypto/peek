---
name: IL2CPP Unity integration
description: How IL2CPP metadata parsing is wired into PEEK — the Unity loader path, C++ parser, JNI bridge, and Kotlin UI.
---

## Overview
When the user taps "Open .so File" → "Unity", they are taken to UnityLoaderActivity which collects both `il2cpp.so` and `global-metadata.dat`, then calls `nativeOpenUnityBinary`.

## New files
- `il2cpp_metadata.h/.cpp` — self-contained C++ IL2CPP parser (ported from Il2CppDumper C#)
- `UnityLoaderActivity.kt` + `activity_unity_loader.xml` — Unity Loader UI
- `dialog_target_type.xml` — "Select Target Type" dialog (Unity / Standard Binary)

## Key decisions

**Supported metadata versions:** 24.2–31 (Unity 2018.3 – Unity 6). Version is read from byte 4 of global-metadata.dat (magic 0xFAB11BAF at byte 0). Versions below 24 and sub-version detection (24.0 vs 24.1) are approximated — all v24 in the file is treated as v24.2.

**Struct layout:** MetaHeader_Core is a packed struct covering the fixed fields up to typeDefinitionsOffset (byte 160). methodsOffset is at byte 48 (always stable). Il2CppMethodDef is 32 bytes (stable v19+).

**Finding CodeRegistration:**
1. Symbol search: looks for `g_CodeRegistration` / `g_MetadataRegistration` in the dynamic symbol table (works for non-stripped libs).
2. Pattern scan fallback: scans LOAD segments for MetaReg_v27 (typesCount == typeDefCount) and CodeReg_v27 (codeGenModulesCount 1–100 with valid pointers). May be slow on very large libs.

**Applying names:** 
- `db->update_function_names_bulk(binary_id, addr_to_name, overwrite=false)` — renames only FUN_/sub_ functions so user-renamed functions are preserved.
- `db->store_signatures(binary_id, sigs)` with source="il2cpp" — makes names available in pseudocode via Ghidra's sig-cache mechanism.

**Name format:** `il2cpp_Namespace.ClassName::MethodName` — the `il2cpp_` prefix distinguishes dumped names from ELF symbols.

**Why:**
The user wanted IDA-like IL2CPP import: load both files, get proper function names, keep the existing disassembler/decompiler pipeline working with the renamed functions.

## AnalysisContext extensions
Two new fields: `is_unity` (bool) and `il2cpp_log` (string diagnostic log). `nativeGetIl2CppLog` exposes the log to the UI for display in the console area.
