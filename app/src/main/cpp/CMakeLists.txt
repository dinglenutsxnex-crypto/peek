cmake_minimum_required(VERSION 3.22.1)
project(peek_native CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# ---------------------------------------------------------------------------
# Capstone 5.0.1 — ARM64/AArch64 only, static, no tests/tools
# ---------------------------------------------------------------------------
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARM64_SUPPORT        ON  CACHE BOOL "" FORCE)
set(CAPSTONE_AARCH64_SUPPORT      ON  CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_SHARED_LIBS    OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_TESTS          OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL         OFF CACHE BOOL "" FORCE)
set(CAPSTONE_INSTALL              OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    capstone
    GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
    GIT_TAG        5.0.1
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(capstone)

# ---------------------------------------------------------------------------
# SQLite 3.46.1 amalgamation — vendored for version control
# ---------------------------------------------------------------------------
FetchContent_Declare(
    sqlite3_amalgamation
    URL https://www.sqlite.org/2024/sqlite-amalgamation-3460100.zip
)
FetchContent_MakeAvailable(sqlite3_amalgamation)

add_library(sqlite3_lib STATIC
    ${sqlite3_amalgamation_SOURCE_DIR}/sqlite3.c
)
target_include_directories(sqlite3_lib PUBLIC
    ${sqlite3_amalgamation_SOURCE_DIR}
)
target_compile_options(sqlite3_lib PRIVATE
    -DSQLITE_THREADSAFE=1
    -DSQLITE_DEFAULT_WAL_SYNCHRONOUS=1
)

# ---------------------------------------------------------------------------
# decompiler_core — Ghidra standalone decompiler (Ghidra_12.1.2_build)
# Source: Ghidra/Features/Decompiler/src/decompile/cpp/
#
# File sets mirror the Makefile's LIBDECOMP_NAMES variable exactly:
#   LIBDECOMP_NAMES = CORE + DECCORE + EXTRA + SLEIGH
#
# Excluded (not in LIBDECOMP_NAMES):
#   GHIDRA group   — Java IPC layer (ghidra_arch, ghidra_process, etc.)
#   SLACOMP group  — SLEIGH *compiler* tool (slgh_compile, slghparse, slghscan)
#   SPECIAL group  — standalone mains/tests (consolemain, sleighexample, test)
#
# Additionally excluded from EXTRA because they need <bfd.h> (GNU binutils,
# unavailable in the Android NDK sysroot):
#   bfd_arch.cc, loadimage_bfd.cc
#
# ruleparse.cc / ruleparse.hh are not committed; they are generated at
# CMake configure time from ruleparse.y using bison (pre-installed on the
# ubuntu-latest CI runner). The generated files live in the CMake binary dir.
#
# Compiled WITH exceptions and RTTI — do NOT add -fno-exceptions/-fno-rtti.
# ---------------------------------------------------------------------------

find_package(BISON REQUIRED)

BISON_TARGET(
    GhidraRuleParser
    ${CMAKE_CURRENT_SOURCE_DIR}/decompiler/ruleparse.y
    ${CMAKE_CURRENT_BINARY_DIR}/decompiler/ruleparse.cc
    DEFINES_FILE ${CMAKE_CURRENT_BINARY_DIR}/decompiler/ruleparse.hh
    COMPILE_FLAGS "-p ruleparse"
)

add_library(decompiler_core STATIC
    # --- CORE ---
    decompiler/xml.cc
    decompiler/marshal.cc
    decompiler/space.cc
    decompiler/float.cc
    decompiler/address.cc
    decompiler/pcoderaw.cc
    decompiler/translate.cc
    decompiler/opcodes.cc
    decompiler/globalcontext.cc
    # --- DECCORE ---
    decompiler/capability.cc
    decompiler/architecture.cc
    decompiler/options.cc
    decompiler/graph.cc
    decompiler/cover.cc
    decompiler/block.cc
    decompiler/cast.cc
    decompiler/typeop.cc
    decompiler/database.cc
    decompiler/cpool.cc
    decompiler/comment.cc
    decompiler/stringmanage.cc
    decompiler/modelrules.cc
    decompiler/fspec.cc
    decompiler/action.cc
    decompiler/loadimage.cc
    decompiler/grammar.cc
    decompiler/varnode.cc
    decompiler/op.cc
    decompiler/type.cc
    decompiler/variable.cc
    decompiler/varmap.cc
    decompiler/jumptable.cc
    decompiler/emulate.cc
    decompiler/emulateutil.cc
    decompiler/flow.cc
    decompiler/userop.cc
    decompiler/expression.cc
    decompiler/multiprecision.cc
    decompiler/funcdata.cc
    decompiler/funcdata_block.cc
    decompiler/funcdata_op.cc
    decompiler/funcdata_varnode.cc
    decompiler/unionresolve.cc
    decompiler/pcodeinject.cc
    decompiler/heritage.cc
    decompiler/prefersplit.cc
    decompiler/rangeutil.cc
    decompiler/ruleaction.cc
    decompiler/subflow.cc
    decompiler/blockaction.cc
    decompiler/merge.cc
    decompiler/double.cc
    decompiler/transform.cc
    decompiler/constseq.cc
    decompiler/bitfield.cc
    decompiler/coreaction.cc
    decompiler/condexe.cc
    decompiler/override.cc
    decompiler/dynamic.cc
    decompiler/crc32.cc
    decompiler/prettyprint.cc
    decompiler/printlanguage.cc
    decompiler/printc.cc
    decompiler/printjava.cc
    decompiler/memstate.cc
    decompiler/opbehavior.cc
    decompiler/paramid.cc
    decompiler/signature.cc
    # --- SLEIGH (runtime decoder, not the .slaspec compiler) ---
    decompiler/sleigh.cc
    decompiler/pcodeparse.cc
    decompiler/pcodecompile.cc
    decompiler/sleighbase.cc
    decompiler/slghsymbol.cc
    decompiler/slghpatexpress.cc
    decompiler/slghpattern.cc
    decompiler/semantics.cc
    decompiler/context.cc
    decompiler/slaformat.cc
    decompiler/compression.cc
    decompiler/filemanage.cc
    # --- EXTRA (remainder of LIBDECOMP_NAMES) ---
    # analyzesigs.cc and codedata.cc are guarded below with if(NOT ANDROID):
    #   both directly #include "loadimage_bfd.hh" → <bfd.h> (GNU binutils,
    #   unavailable in the Android NDK sysroot).  They are pure CLI-shell
    #   capability registrations (IfaceCapability subclasses) and are never
    #   called by the core decompile pipeline.
    # bfd_arch.cc and loadimage_bfd.cc are absent from this source tree
    #   (only their .hh headers were vendored); nothing includes them.
    decompiler/callgraph.cc
    decompiler/ifacedecomp.cc
    decompiler/ifaceterm.cc
    decompiler/inject_sleigh.cc
    decompiler/interface.cc
    decompiler/libdecomp.cc
    decompiler/loadimage_xml.cc
    decompiler/raw_arch.cc
    decompiler/rulecompile.cc
    decompiler/sleigh_arch.cc
    decompiler/testfunction.cc
    decompiler/unify.cc
    decompiler/xml_arch.cc
    # ruleparse.cc + ruleparse.hh — generated by bison at configure time
    ${BISON_GhidraRuleParser_OUTPUTS}
)

# BFD-dependent CLI files — excluded on Android (no GNU binutils in NDK sysroot)
if(NOT ANDROID)
    target_sources(decompiler_core PRIVATE
        decompiler/analyzesigs.cc
        decompiler/codedata.cc
    )
endif()

target_include_directories(decompiler_core PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/decompiler
    ${CMAKE_CURRENT_BINARY_DIR}/decompiler
)

target_compile_options(decompiler_core PRIVATE
    -Wall
    -Wextra
    # Intentionally no -fno-exceptions and no -fno-rtti:
    # decompiler_core needs both enabled for the Ghidra decompiler sources.
)

# ---------------------------------------------------------------------------
# peek_native shared library
# ---------------------------------------------------------------------------
add_library(peek_native SHARED
    elf_parser.cpp
    disassembler.cpp
    xref_detector.cpp
    db_cache.cpp
    decompiler_bridge.cpp
    jni_annotator.cpp
    algo_detector.cpp
    crash_handler.cpp
    il2cpp_metadata.cpp
    peek_jni.cpp
)

# decompiler_bridge.cpp wraps Ghidra headers and must be compiled WITH
# C++ exceptions and RTTI (the decompiler_core library requires both).
# The per-file property overrides the target-wide -fno-exceptions/-fno-rtti
# set below for the other translation units.
set_source_files_properties(
    decompiler_bridge.cpp
    PROPERTIES COMPILE_FLAGS "-fexceptions -frtti"
)

target_include_directories(peek_native PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/decompiler
    ${CMAKE_CURRENT_BINARY_DIR}/decompiler
    ${capstone_SOURCE_DIR}/include
    ${sqlite3_amalgamation_SOURCE_DIR}
)

target_link_libraries(peek_native
    decompiler_core
    capstone
    sqlite3_lib
    android
    log
    z
)

target_compile_options(peek_native PRIVATE
    -Wall
    -Wextra
    -fno-exceptions
    -fno-rtti
)
