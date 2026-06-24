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
# peek_native shared library
# ---------------------------------------------------------------------------
add_library(peek_native SHARED
    elf_parser.cpp
    disassembler.cpp
    xref_detector.cpp
    db_cache.cpp
    peek_jni.cpp
)

target_include_directories(peek_native PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${capstone_SOURCE_DIR}/include
    ${sqlite3_amalgamation_SOURCE_DIR}
)

target_link_libraries(peek_native
    capstone
    sqlite3_lib
    android
    log
)

target_compile_options(peek_native PRIVATE
    -Wall
    -Wextra
    -fno-exceptions
    -fno-rtti
)
