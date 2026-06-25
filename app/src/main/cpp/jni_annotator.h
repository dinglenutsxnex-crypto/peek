#pragma once
#include <string>

/*
 * jni_annotator — post-processes raw Ghidra pseudocode to apply JNI-aware
 * type annotations.
 *
 * Detection is based solely on the exported function name:
 *   JNI_OnLoad   → jint JNI_OnLoad(JavaVM *vm, void *reserved)
 *   JNI_OnUnload → void JNI_OnUnload(JavaVM *vm, void *reserved)
 *   Java_*       → first two params become (JNIEnv *env, jobject thiz)
 *
 * Nothing is hardcoded to a specific binary.  If the name does not match
 * any JNI pattern the input is returned unchanged.
 *
 * The result is safe to cache in the DB — call once, store result.
 */
std::string jni_annotate(const std::string& func_name,
                          const std::string& pseudocode);
