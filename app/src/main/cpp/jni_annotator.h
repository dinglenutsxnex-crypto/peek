#pragma once
#include <string>

/*
 * jni_annotator — post-processes raw Ghidra pseudocode with JNI-aware
 * type annotations, full vtable call resolution, and JNI constant naming.
 *
 * Detection is based solely on the exported function name:
 *   JNI_OnLoad   → jint JNI_OnLoad(JavaVM *vm, void *reserved)
 *   JNI_OnUnload → void JNI_OnUnload(JavaVM *vm, void *reserved)
 *   Java_*       → (JNIEnv *env, jobject thiz, ...)
 *
 * Vtable calls like (**(code **)(*vm + 0x30))(vm,...) are resolved to
 * (*vm)->GetEnv(vm,...) using the full 232-entry JNI 1.6 function table.
 *
 * JNI version constants (0x10006 etc.) are replaced with their #define names.
 *
 * Returns input unchanged if the name does not match any JNI pattern.
 * Result is safe to cache — call once, store result.
 */
std::string jni_annotate(const std::string& func_name,
                          const std::string& pseudocode);

/*
 * Version tag prepended to every cached pseudocode entry.
 * When the stored pseudocode does not begin with this tag the cache entry
 * is treated as stale and re-decompilation is triggered automatically.
 */
extern const char* JNI_ANNOTATOR_CACHE_TAG;
