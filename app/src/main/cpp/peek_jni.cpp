/**
 * peek_jni.cpp
 *
 * JNI bridge between the Kotlin UI layer and the C++ analysis engine.
 *
 * JNI contract (exposed to Kotlin via PeekNative.kt):
 *
 *   nativeOpenBinary(path: String, dbDir: String): Long
 *       → Opens & analyses (or loads from cache) the given .so file.
 *         Returns a handle (opaque pointer cast to jlong), or 0 on error.
 *
 *   nativeGetFunctionList(handle: Long): LongArray
 *       → Returns an interleaved array [id, address, size, nameLen, …]
 *         encoded as a flat LongArray.  Kotlin decodes via PeekNative.
 *
 *   nativeGetFunctionNames(handle: Long): Array<String>
 *       → Parallel string array to getFunctionList.
 *
 *   nativeGetInstructions(handle: Long, funcId: Long, limit: Int, offset: Int): LongArray
 *       → Interleaved [address, size, …] flat array.
 *
 *   nativeGetInstructionStrings(handle: Long, funcId: Long, limit: Int, offset: Int): Array<String>
 *       → Parallel string array [bytesHex, mnemonic, operands, bytesHex, …].
 *
 *   nativeGetXrefs(handle: Long, address: Long): LongArray
 *       → [fromAddress, toAddress, fromAddress, toAddress, …]
 *
 *   nativeGetXrefTypes(handle: Long, address: Long): Array<String>
 *       → Parallel ref_type string per xref pair.
 *
 *   nativeGetSymbols(handle: Long): LongArray + nativeGetSymbolStrings(…)
 *
 *   nativeGetInstructionCount(handle: Long, funcId: Long): Long
 *
 *   nativeCloseBinary(handle: Long)
 *
 *   nativeGetLastError(handle: Long): String
 */

#include "elf_parser.h"
#include "disassembler.h"
#include "xref_detector.h"
#include "db_cache.h"

#include <jni.h>
#include <android/log.h>
#include <string>
#include <memory>
#include <sstream>

#define TAG "PeekJNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ---------------------------------------------------------------------------
// Analysis context — one per opened binary
// ---------------------------------------------------------------------------

struct AnalysisContext {
    std::string     file_path;
    std::string     file_hash;
    int64_t         binary_id = -1;
    std::string     last_error;
    std::unique_ptr<AnalysisDb> db;
};

static std::string jstr(JNIEnv* env, jstring s) {
    if (!s) return "";
    const char* c = env->GetStringUTFChars(s, nullptr);
    std::string result = c;
    env->ReleaseStringUTFChars(s, c);
    return result;
}

// ---------------------------------------------------------------------------
// Full analysis pipeline: parse ELF → disassemble → detect xrefs → store DB
// ---------------------------------------------------------------------------

static bool run_analysis(AnalysisContext& ctx) {
    LOGI("Starting analysis of %s", ctx.file_path.c_str());

    ElfParseResult elf = elf_parse(ctx.file_path);
    if (!elf.ok) {
        ctx.last_error = "ELF parse error: " + elf.error;
        LOGE("%s", ctx.last_error.c_str());
        return false;
    }

    ctx.binary_id = ctx.db->insert_binary(ctx.file_hash, ctx.file_path);
    if (ctx.binary_id < 0) {
        ctx.last_error = "DB insert binary failed: " + ctx.db->last_error();
        return false;
    }

    // Store symbols
    ctx.db->store_symbols(ctx.binary_id, elf.symbols);

    // Store functions
    ctx.db->store_functions(ctx.binary_id, elf.functions);

    // Collect all xrefs from all executable sections
    std::vector<Xref> all_xrefs;

    // Find all executable sections for bounds checking in xref detection
    uint64_t code_base = UINT64_MAX, code_end = 0;
    for (const auto& sec : elf.sections) {
        if (sec.is_executable() && sec.size > 0) {
            if (sec.address < code_base) code_base = sec.address;
            if (sec.address + sec.size > code_end) code_end = sec.address + sec.size;
        }
    }

    // Disassemble each function, store instructions + collect xrefs
    for (const auto& fn : elf.functions) {
        if (fn.size == 0 || fn.address == 0) continue;

        // Find the section that contains this function
        uint64_t file_offset = 0;
        bool found_section = false;
        for (const auto& sec : elf.sections) {
            if (!sec.is_executable()) continue;
            if (fn.address >= sec.address && fn.address < sec.address + sec.size) {
                uint64_t va_off = fn.address - sec.address;
                file_offset = sec.offset + va_off;
                found_section = true;
                break;
            }
        }
        if (!found_section || file_offset + fn.size > elf.data.size()) continue;

        DisasmResult dr = disassemble_arm64(
            elf.data.data() + file_offset,
            (size_t)fn.size,
            fn.address
        );
        if (!dr.ok || dr.instructions.empty()) continue;

        // Get the function's DB id and tag instructions
        int64_t func_id = ctx.db->get_function_id(ctx.binary_id, fn.address);
        if (func_id < 0) continue;

        for (auto& insn : dr.instructions) insn.function_id = (uint32_t)func_id;
        ctx.db->store_instructions(dr.instructions);

        // Detect xrefs from this function
        auto xrefs = detect_xrefs(dr.instructions, code_base, code_end);
        all_xrefs.insert(all_xrefs.end(), xrefs.begin(), xrefs.end());
    }

    ctx.db->store_xrefs(ctx.binary_id, all_xrefs);
    LOGI("Analysis complete: binary_id=%lld, xrefs=%zu", (long long)ctx.binary_id, all_xrefs.size());
    return true;
}

// ---------------------------------------------------------------------------
// JNI implementations
// ---------------------------------------------------------------------------

extern "C" {

JNIEXPORT jlong JNICALL
Java_com_nex_peek_PeekNative_nativeOpenBinary(JNIEnv* env, jobject,
                                               jstring jpath, jstring jdb_dir) {
    std::string path   = jstr(env, jpath);
    std::string db_dir = jstr(env, jdb_dir);

    auto* ctx = new AnalysisContext();
    ctx->file_path = path;
    ctx->file_hash = sha256_file(path);
    if (ctx->file_hash.empty()) {
        ctx->last_error = "Could not hash file: " + path;
        return reinterpret_cast<jlong>(ctx);
    }

    std::string db_path = db_dir + "/peek_cache.db";
    ctx->db = std::make_unique<AnalysisDb>(db_path);
    if (!ctx->db->open()) {
        ctx->last_error = "Could not open DB: " + ctx->db->last_error();
        return reinterpret_cast<jlong>(ctx);
    }

    // Check cache
    int64_t cached_id = ctx->db->find_binary(ctx->file_hash);
    if (cached_id >= 0) {
        ctx->binary_id = cached_id;
        LOGI("Cache hit for %s (binary_id=%lld)", path.c_str(), (long long)cached_id);
    } else {
        LOGI("Cache miss, running analysis for %s", path.c_str());
        if (!run_analysis(*ctx)) {
            LOGE("Analysis failed: %s", ctx->last_error.c_str());
        }
    }

    return reinterpret_cast<jlong>(ctx);
}

JNIEXPORT void JNICALL
Java_com_nex_peek_PeekNative_nativeCloseBinary(JNIEnv*, jobject, jlong handle) {
    if (handle == 0) return;
    auto* ctx = reinterpret_cast<AnalysisContext*>(handle);
    delete ctx;
}

JNIEXPORT jstring JNICALL
Java_com_nex_peek_PeekNative_nativeGetLastError(JNIEnv* env, jobject, jlong handle) {
    if (handle == 0) return env->NewStringUTF("null handle");
    auto* ctx = reinterpret_cast<AnalysisContext*>(handle);
    return env->NewStringUTF(ctx->last_error.c_str());
}

// Returns flat LongArray: [id, address, size, id, address, size, ...]
JNIEXPORT jlongArray JNICALL
Java_com_nex_peek_PeekNative_nativeGetFunctionList(JNIEnv* env, jobject, jlong handle) {
    if (handle == 0) return env->NewLongArray(0);
    auto* ctx = reinterpret_cast<AnalysisContext*>(handle);
    if (ctx->binary_id < 0) return env->NewLongArray(0);

    auto fns = ctx->db->get_functions(ctx->binary_id);
    jsize n = (jsize)(fns.size() * 3);
    jlongArray arr = env->NewLongArray(n);
    if (n == 0) return arr;

    std::vector<jlong> buf(n);
    for (size_t i = 0; i < fns.size(); ++i) {
        buf[i*3 + 0] = (jlong)fns[i].id;
        buf[i*3 + 1] = (jlong)fns[i].address;
        buf[i*3 + 2] = (jlong)fns[i].size;
    }
    env->SetLongArrayRegion(arr, 0, n, buf.data());
    return arr;
}

// Parallel string array: one name per function
JNIEXPORT jobjectArray JNICALL
Java_com_nex_peek_PeekNative_nativeGetFunctionNames(JNIEnv* env, jobject, jlong handle) {
    jclass strClass = env->FindClass("java/lang/String");
    if (handle == 0) return env->NewObjectArray(0, strClass, nullptr);
    auto* ctx = reinterpret_cast<AnalysisContext*>(handle);
    if (ctx->binary_id < 0) return env->NewObjectArray(0, strClass, nullptr);

    auto fns = ctx->db->get_functions(ctx->binary_id);
    jobjectArray arr = env->NewObjectArray((jsize)fns.size(), strClass, nullptr);
    for (size_t i = 0; i < fns.size(); ++i) {
        jstring s = env->NewStringUTF(fns[i].name.c_str());
        env->SetObjectArrayElement(arr, (jsize)i, s);
        env->DeleteLocalRef(s);
    }
    return arr;
}

// Returns flat LongArray: [address, size, address, size, ...]
JNIEXPORT jlongArray JNICALL
Java_com_nex_peek_PeekNative_nativeGetInstructions(JNIEnv* env, jobject,
                                                    jlong handle, jlong func_id,
                                                    jint limit, jint offset) {
    if (handle == 0) return env->NewLongArray(0);
    auto* ctx = reinterpret_cast<AnalysisContext*>(handle);

    auto insns = ctx->db->get_instructions((int64_t)func_id, (int)limit, (int)offset);
    jsize n = (jsize)(insns.size() * 2);
    jlongArray arr = env->NewLongArray(n);
    if (n == 0) return arr;

    std::vector<jlong> buf(n);
    for (size_t i = 0; i < insns.size(); ++i) {
        buf[i*2 + 0] = (jlong)insns[i].address;
        buf[i*2 + 1] = (jlong)insns[i].size;
    }
    env->SetLongArrayRegion(arr, 0, n, buf.data());
    return arr;
}

// Parallel string array: [bytesHex, mnemonic, operands, ...]  (3 per instruction)
JNIEXPORT jobjectArray JNICALL
Java_com_nex_peek_PeekNative_nativeGetInstructionStrings(JNIEnv* env, jobject,
                                                          jlong handle, jlong func_id,
                                                          jint limit, jint offset) {
    jclass strClass = env->FindClass("java/lang/String");
    if (handle == 0) return env->NewObjectArray(0, strClass, nullptr);
    auto* ctx = reinterpret_cast<AnalysisContext*>(handle);

    auto insns = ctx->db->get_instructions((int64_t)func_id, (int)limit, (int)offset);
    jsize n = (jsize)(insns.size() * 3);
    jobjectArray arr = env->NewObjectArray(n, strClass, nullptr);
    for (size_t i = 0; i < insns.size(); ++i) {
        auto set = [&](jsize idx, const std::string& val) {
            jstring s = env->NewStringUTF(val.c_str());
            env->SetObjectArrayElement(arr, idx, s);
            env->DeleteLocalRef(s);
        };
        set((jsize)(i*3 + 0), insns[i].bytes_hex);
        set((jsize)(i*3 + 1), insns[i].mnemonic);
        set((jsize)(i*3 + 2), insns[i].operands);
    }
    return arr;
}

JNIEXPORT jlong JNICALL
Java_com_nex_peek_PeekNative_nativeGetInstructionCount(JNIEnv*, jobject,
                                                        jlong handle, jlong func_id) {
    if (handle == 0) return 0;
    auto* ctx = reinterpret_cast<AnalysisContext*>(handle);
    return (jlong)ctx->db->get_instruction_count((int64_t)func_id);
}

// Returns flat LongArray: [fromAddr, toAddr, fromAddr, toAddr, ...]
JNIEXPORT jlongArray JNICALL
Java_com_nex_peek_PeekNative_nativeGetXrefs(JNIEnv* env, jobject,
                                             jlong handle, jlong address) {
    if (handle == 0) return env->NewLongArray(0);
    auto* ctx = reinterpret_cast<AnalysisContext*>(handle);
    if (ctx->binary_id < 0) return env->NewLongArray(0);

    auto xrefs = ctx->db->get_xrefs(ctx->binary_id, (uint64_t)address);
    jsize n = (jsize)(xrefs.size() * 2);
    jlongArray arr = env->NewLongArray(n);
    if (n == 0) return arr;

    std::vector<jlong> buf(n);
    for (size_t i = 0; i < xrefs.size(); ++i) {
        buf[i*2 + 0] = (jlong)xrefs[i].from_address;
        buf[i*2 + 1] = (jlong)xrefs[i].to_address;
    }
    env->SetLongArrayRegion(arr, 0, n, buf.data());
    return arr;
}

JNIEXPORT jobjectArray JNICALL
Java_com_nex_peek_PeekNative_nativeGetXrefTypes(JNIEnv* env, jobject,
                                                 jlong handle, jlong address) {
    jclass strClass = env->FindClass("java/lang/String");
    if (handle == 0) return env->NewObjectArray(0, strClass, nullptr);
    auto* ctx = reinterpret_cast<AnalysisContext*>(handle);
    if (ctx->binary_id < 0) return env->NewObjectArray(0, strClass, nullptr);

    auto xrefs = ctx->db->get_xrefs(ctx->binary_id, (uint64_t)address);
    jobjectArray arr = env->NewObjectArray((jsize)xrefs.size(), strClass, nullptr);
    for (size_t i = 0; i < xrefs.size(); ++i) {
        jstring s = env->NewStringUTF(xrefs[i].ref_type.c_str());
        env->SetObjectArrayElement(arr, (jsize)i, s);
        env->DeleteLocalRef(s);
    }
    return arr;
}

// Returns flat LongArray: [address, is_import, address, ...]  (2 per symbol)
JNIEXPORT jlongArray JNICALL
Java_com_nex_peek_PeekNative_nativeGetSymbols(JNIEnv* env, jobject, jlong handle) {
    if (handle == 0) return env->NewLongArray(0);
    auto* ctx = reinterpret_cast<AnalysisContext*>(handle);
    if (ctx->binary_id < 0) return env->NewLongArray(0);

    auto syms = ctx->db->get_symbols(ctx->binary_id);
    jsize n = (jsize)(syms.size() * 2);
    jlongArray arr = env->NewLongArray(n);
    if (n == 0) return arr;

    std::vector<jlong> buf(n);
    for (size_t i = 0; i < syms.size(); ++i) {
        buf[i*2 + 0] = (jlong)syms[i].address;
        buf[i*2 + 1] = syms[i].is_import ? 1L : 0L;
    }
    env->SetLongArrayRegion(arr, 0, n, buf.data());
    return arr;
}

// Parallel string array: [name, typeStr, name, typeStr, ...]  (2 per symbol)
JNIEXPORT jobjectArray JNICALL
Java_com_nex_peek_PeekNative_nativeGetSymbolStrings(JNIEnv* env, jobject, jlong handle) {
    jclass strClass = env->FindClass("java/lang/String");
    if (handle == 0) return env->NewObjectArray(0, strClass, nullptr);
    auto* ctx = reinterpret_cast<AnalysisContext*>(handle);
    if (ctx->binary_id < 0) return env->NewObjectArray(0, strClass, nullptr);

    auto syms = ctx->db->get_symbols(ctx->binary_id);
    jsize n = (jsize)(syms.size() * 2);
    jobjectArray arr = env->NewObjectArray(n, strClass, nullptr);
    for (size_t i = 0; i < syms.size(); ++i) {
        auto set = [&](jsize idx, const std::string& val) {
            jstring s = env->NewStringUTF(val.c_str());
            env->SetObjectArrayElement(arr, idx, s);
            env->DeleteLocalRef(s);
        };
        set((jsize)(i*2 + 0), syms[i].name);
        set((jsize)(i*2 + 1), syms[i].type_str);
    }
    return arr;
}

} // extern "C"
