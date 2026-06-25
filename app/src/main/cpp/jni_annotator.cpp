#include "jni_annotator.h"

#include <cctype>
#include <cstdio>    // snprintf
#include <cstdlib>   // strtoull, atoi
#include <cstring>   // strlen
#include <map>
#include <sstream>
#include <vector>

// ---------------------------------------------------------------------------
// Character helpers
// ---------------------------------------------------------------------------

static bool is_id(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
}

static bool is_hex(char c) {
    return std::isxdigit(static_cast<unsigned char>(c)) != 0;
}

// ---------------------------------------------------------------------------
// Whole-word identifier replacement
// ---------------------------------------------------------------------------

static std::string replace_ident(const std::string& src,
                                  const std::string& from,
                                  const std::string& to) {
    if (from.empty()) return src;
    std::string out;
    out.reserve(src.size());
    const size_t flen = from.size();
    size_t pos = 0;
    while (pos < src.size()) {
        size_t f = src.find(from, pos);
        if (f == std::string::npos) { out.append(src, pos, std::string::npos); break; }
        bool left_ok  = (f == 0)               || !is_id(src[f - 1]);
        bool right_ok = (f + flen >= src.size()) || !is_id(src[f + flen]);
        if (left_ok && right_ok) {
            out.append(src, pos, f - pos);
            out.append(to);
            pos = f + flen;
        } else {
            out.append(src, pos, f - pos + 1);
            pos = f + 1;
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// Signature-line param-type replacement
// ---------------------------------------------------------------------------

static std::string replace_param_in_sig(const std::string& sig,
                                         const std::string& param_tag,
                                         const std::string& replacement) {
    const size_t flen = param_tag.size();
    size_t pos = 0;
    while (pos < sig.size()) {
        size_t f = sig.find(param_tag, pos);
        if (f == std::string::npos) return sig;
        bool left_ok  = (f == 0)               || !is_id(sig[f - 1]);
        bool right_ok = (f + flen >= sig.size()) || !is_id(sig[f + flen]);
        if (!left_ok || !right_ok) { pos = f + 1; continue; }

        ssize_t scan = static_cast<ssize_t>(f) - 1;
        while (scan >= 0 && (sig[scan]==' '||sig[scan]=='\t'||sig[scan]=='*')) --scan;
        while (scan >= 0 && is_id(sig[scan])) --scan;
        while (scan >= 0 && (sig[scan]==' '||sig[scan]=='\t')) --scan;
        if (scan >= 0 && is_id(sig[scan])) {
            while (scan >= 0 && is_id(sig[scan])) --scan;
            while (scan >= 0 && (sig[scan]==' '||sig[scan]=='\t')) --scan;
        }
        size_t type_start = static_cast<size_t>(scan + 1);

        std::string prefix(sig, 0, type_start);
        while (!prefix.empty() && (prefix.back()==' '||prefix.back()=='\t'))
            prefix.pop_back();
        std::string out;
        out.reserve(sig.size());
        out.append(prefix);
        if (!prefix.empty() && prefix.back() == ',') out += ' ';
        out.append(replacement);
        out.append(sig, f + flen, sig.size() - f - flen);
        return out;
    }
    return sig;
}

// ---------------------------------------------------------------------------
// Line utilities
// ---------------------------------------------------------------------------

static std::vector<std::string> split_lines(const std::string& text) {
    std::vector<std::string> lines;
    std::istringstream ss(text);
    std::string line;
    while (std::getline(ss, line)) lines.push_back(line);
    return lines;
}

static std::string join_lines(const std::vector<std::string>& lines) {
    std::string out;
    for (size_t i = 0; i < lines.size(); ++i) {
        out += lines[i];
        if (i + 1 < lines.size()) out += '\n';
    }
    return out;
}

static size_t find_sig_line(const std::vector<std::string>& lines,
                              const std::string& funcname) {
    const size_t flen = funcname.size();
    for (size_t i = 0; i < lines.size(); ++i) {
        const std::string& l = lines[i];
        size_t f = 0;
        while (f < l.size()) {
            size_t found = l.find(funcname, f);
            if (found == std::string::npos) break;
            bool left_ok  = (found == 0)              || !is_id(l[found - 1]);
            bool right_ok = (found + flen >= l.size()) || !is_id(l[found + flen]);
            if (left_ok && right_ok) {
                size_t j = found + flen;
                while (j < l.size() && l[j] == ' ') ++j;
                if (j < l.size() && l[j] == '(') return i;
            }
            f = found + 1;
        }
    }
    return lines.size();
}

// ---------------------------------------------------------------------------
// JNI vtable tables
// ---------------------------------------------------------------------------

struct VtableEntry { uint64_t offset; const char* name; };

static const VtableEntry kJavaVMTable[] = {
    {0x18, "DestroyJavaVM"},
    {0x20, "AttachCurrentThread"},
    {0x28, "DetachCurrentThread"},
    {0x30, "GetEnv"},
    {0x38, "AttachCurrentThreadAsDaemon"},
};
static const size_t kJavaVMTableSize = sizeof(kJavaVMTable)/sizeof(kJavaVMTable[0]);

// Full JNI 1.6 JNIEnv function table (232 entries, 64-bit offsets = index*8).
static const VtableEntry kJNIEnvTable[] = {
    {0x020, "GetVersion"},
    {0x028, "DefineClass"},
    {0x030, "FindClass"},
    {0x038, "FromReflectedMethod"},
    {0x040, "FromReflectedField"},
    {0x048, "ToReflectedMethod"},
    {0x050, "GetSuperclass"},
    {0x058, "IsAssignableFrom"},
    {0x060, "ToReflectedField"},
    {0x068, "Throw"},
    {0x070, "ThrowNew"},
    {0x078, "ExceptionOccurred"},
    {0x080, "ExceptionDescribe"},
    {0x088, "ExceptionClear"},
    {0x090, "FatalError"},
    {0x098, "PushLocalFrame"},
    {0x0a0, "PopLocalFrame"},
    {0x0a8, "NewGlobalRef"},
    {0x0b0, "DeleteGlobalRef"},
    {0x0b8, "DeleteLocalRef"},
    {0x0c0, "IsSameObject"},
    {0x0c8, "NewLocalRef"},
    {0x0d0, "EnsureLocalCapacity"},
    {0x0d8, "AllocObject"},
    {0x0e0, "NewObject"},
    {0x0e8, "NewObjectV"},
    {0x0f0, "NewObjectA"},
    {0x0f8, "GetObjectClass"},
    {0x100, "IsInstanceOf"},
    {0x108, "GetMethodID"},
    {0x110, "CallObjectMethod"},
    {0x118, "CallObjectMethodV"},
    {0x120, "CallObjectMethodA"},
    {0x128, "CallBooleanMethod"},
    {0x130, "CallBooleanMethodV"},
    {0x138, "CallBooleanMethodA"},
    {0x140, "CallByteMethod"},
    {0x148, "CallByteMethodV"},
    {0x150, "CallByteMethodA"},
    {0x158, "CallCharMethod"},
    {0x160, "CallCharMethodV"},
    {0x168, "CallCharMethodA"},
    {0x170, "CallShortMethod"},
    {0x178, "CallShortMethodV"},
    {0x180, "CallShortMethodA"},
    {0x188, "CallIntMethod"},
    {0x190, "CallIntMethodV"},
    {0x198, "CallIntMethodA"},
    {0x1a0, "CallLongMethod"},
    {0x1a8, "CallLongMethodV"},
    {0x1b0, "CallLongMethodA"},
    {0x1b8, "CallFloatMethod"},
    {0x1c0, "CallFloatMethodV"},
    {0x1c8, "CallFloatMethodA"},
    {0x1d0, "CallDoubleMethod"},
    {0x1d8, "CallDoubleMethodV"},
    {0x1e0, "CallDoubleMethodA"},
    {0x1e8, "CallVoidMethod"},
    {0x1f0, "CallVoidMethodV"},
    {0x1f8, "CallVoidMethodA"},
    {0x200, "CallNonvirtualObjectMethod"},
    {0x208, "CallNonvirtualObjectMethodV"},
    {0x210, "CallNonvirtualObjectMethodA"},
    {0x218, "CallNonvirtualBooleanMethod"},
    {0x220, "CallNonvirtualBooleanMethodV"},
    {0x228, "CallNonvirtualBooleanMethodA"},
    {0x230, "CallNonvirtualByteMethod"},
    {0x238, "CallNonvirtualByteMethodV"},
    {0x240, "CallNonvirtualByteMethodA"},
    {0x248, "CallNonvirtualCharMethod"},
    {0x250, "CallNonvirtualCharMethodV"},
    {0x258, "CallNonvirtualCharMethodA"},
    {0x260, "CallNonvirtualShortMethod"},
    {0x268, "CallNonvirtualShortMethodV"},
    {0x270, "CallNonvirtualShortMethodA"},
    {0x278, "CallNonvirtualIntMethod"},
    {0x280, "CallNonvirtualIntMethodV"},
    {0x288, "CallNonvirtualIntMethodA"},
    {0x290, "CallNonvirtualLongMethod"},
    {0x298, "CallNonvirtualLongMethodV"},
    {0x2a0, "CallNonvirtualLongMethodA"},
    {0x2a8, "CallNonvirtualFloatMethod"},
    {0x2b0, "CallNonvirtualFloatMethodV"},
    {0x2b8, "CallNonvirtualFloatMethodA"},
    {0x2c0, "CallNonvirtualDoubleMethod"},
    {0x2c8, "CallNonvirtualDoubleMethodV"},
    {0x2d0, "CallNonvirtualDoubleMethodA"},
    {0x2d8, "CallNonvirtualVoidMethod"},
    {0x2e0, "CallNonvirtualVoidMethodV"},
    {0x2e8, "CallNonvirtualVoidMethodA"},
    {0x2f0, "GetFieldID"},
    {0x2f8, "GetObjectField"},
    {0x300, "GetBooleanField"},
    {0x308, "GetByteField"},
    {0x310, "GetCharField"},
    {0x318, "GetShortField"},
    {0x320, "GetIntField"},
    {0x328, "GetLongField"},
    {0x330, "GetFloatField"},
    {0x338, "GetDoubleField"},
    {0x340, "SetObjectField"},
    {0x348, "SetBooleanField"},
    {0x350, "SetByteField"},
    {0x358, "SetCharField"},
    {0x360, "SetShortField"},
    {0x368, "SetIntField"},
    {0x370, "SetLongField"},
    {0x378, "SetFloatField"},
    {0x380, "SetDoubleField"},
    {0x388, "GetStaticMethodID"},
    {0x390, "CallStaticObjectMethod"},
    {0x398, "CallStaticObjectMethodV"},
    {0x3a0, "CallStaticObjectMethodA"},
    {0x3a8, "CallStaticBooleanMethod"},
    {0x3b0, "CallStaticBooleanMethodV"},
    {0x3b8, "CallStaticBooleanMethodA"},
    {0x3c0, "CallStaticByteMethod"},
    {0x3c8, "CallStaticByteMethodV"},
    {0x3d0, "CallStaticByteMethodA"},
    {0x3d8, "CallStaticCharMethod"},
    {0x3e0, "CallStaticCharMethodV"},
    {0x3e8, "CallStaticCharMethodA"},
    {0x3f0, "CallStaticShortMethod"},
    {0x3f8, "CallStaticShortMethodV"},
    {0x400, "CallStaticShortMethodA"},
    {0x408, "CallStaticIntMethod"},
    {0x410, "CallStaticIntMethodV"},
    {0x418, "CallStaticIntMethodA"},
    {0x420, "CallStaticLongMethod"},
    {0x428, "CallStaticLongMethodV"},
    {0x430, "CallStaticLongMethodA"},
    {0x438, "CallStaticFloatMethod"},
    {0x440, "CallStaticFloatMethodV"},
    {0x448, "CallStaticFloatMethodA"},
    {0x450, "CallStaticDoubleMethod"},
    {0x458, "CallStaticDoubleMethodV"},
    {0x460, "CallStaticDoubleMethodA"},
    {0x468, "CallStaticVoidMethod"},
    {0x470, "CallStaticVoidMethodV"},
    {0x478, "CallStaticVoidMethodA"},
    {0x480, "GetStaticFieldID"},
    {0x488, "GetStaticObjectField"},
    {0x490, "GetStaticBooleanField"},
    {0x498, "GetStaticByteField"},
    {0x4a0, "GetStaticCharField"},
    {0x4a8, "GetStaticShortField"},
    {0x4b0, "GetStaticIntField"},
    {0x4b8, "GetStaticLongField"},
    {0x4c0, "GetStaticFloatField"},
    {0x4c8, "GetStaticDoubleField"},
    {0x4d0, "SetStaticObjectField"},
    {0x4d8, "SetStaticBooleanField"},
    {0x4e0, "SetStaticByteField"},
    {0x4e8, "SetStaticCharField"},
    {0x4f0, "SetStaticShortField"},
    {0x4f8, "SetStaticIntField"},
    {0x500, "SetStaticLongField"},
    {0x508, "SetStaticFloatField"},
    {0x510, "SetStaticDoubleField"},
    {0x518, "NewString"},
    {0x520, "GetStringLength"},
    {0x528, "GetStringChars"},
    {0x530, "ReleaseStringChars"},
    {0x538, "NewStringUTF"},
    {0x540, "GetStringUTFLength"},
    {0x548, "GetStringUTFChars"},
    {0x550, "ReleaseStringUTFChars"},
    {0x558, "GetArrayLength"},
    {0x560, "NewObjectArray"},
    {0x568, "GetObjectArrayElement"},
    {0x570, "SetObjectArrayElement"},
    {0x578, "NewBooleanArray"},
    {0x580, "NewByteArray"},
    {0x588, "NewCharArray"},
    {0x590, "NewShortArray"},
    {0x598, "NewIntArray"},
    {0x5a0, "NewLongArray"},
    {0x5a8, "NewFloatArray"},
    {0x5b0, "NewDoubleArray"},
    {0x5b8, "GetBooleanArrayElements"},
    {0x5c0, "GetByteArrayElements"},
    {0x5c8, "GetCharArrayElements"},
    {0x5d0, "GetShortArrayElements"},
    {0x5d8, "GetIntArrayElements"},
    {0x5e0, "GetLongArrayElements"},
    {0x5e8, "GetFloatArrayElements"},
    {0x5f0, "GetDoubleArrayElements"},
    {0x5f8, "ReleaseBooleanArrayElements"},
    {0x600, "ReleaseByteArrayElements"},
    {0x608, "ReleaseCharArrayElements"},
    {0x610, "ReleaseShortArrayElements"},
    {0x618, "ReleaseIntArrayElements"},
    {0x620, "ReleaseLongArrayElements"},
    {0x628, "ReleaseFloatArrayElements"},
    {0x630, "ReleaseDoubleArrayElements"},
    {0x638, "GetBooleanArrayRegion"},
    {0x640, "GetByteArrayRegion"},
    {0x648, "GetCharArrayRegion"},
    {0x650, "GetShortArrayRegion"},
    {0x658, "GetIntArrayRegion"},
    {0x660, "GetLongArrayRegion"},
    {0x668, "GetFloatArrayRegion"},
    {0x670, "GetDoubleArrayRegion"},
    {0x678, "SetBooleanArrayRegion"},
    {0x680, "SetByteArrayRegion"},
    {0x688, "SetCharArrayRegion"},
    {0x690, "SetShortArrayRegion"},
    {0x698, "SetIntArrayRegion"},
    {0x6a0, "SetLongArrayRegion"},
    {0x6a8, "SetFloatArrayRegion"},
    {0x6b0, "SetDoubleArrayRegion"},
    {0x6b8, "RegisterNatives"},
    {0x6c0, "UnregisterNatives"},
    {0x6c8, "MonitorEnter"},
    {0x6d0, "MonitorExit"},
    {0x6d8, "GetJavaVM"},
    {0x6e0, "GetStringRegion"},
    {0x6e8, "GetStringUTFRegion"},
    {0x6f0, "GetPrimitiveArrayCritical"},
    {0x6f8, "ReleasePrimitiveArrayCritical"},
    {0x700, "GetStringCritical"},
    {0x708, "ReleaseStringCritical"},
    {0x710, "NewWeakGlobalRef"},
    {0x718, "DeleteWeakGlobalRef"},
    {0x720, "ExceptionCheck"},
    {0x728, "NewDirectByteBuffer"},
    {0x730, "GetDirectBufferAddress"},
    {0x738, "GetDirectBufferCapacity"},
    {0x740, "GetObjectRefType"},
};
static const size_t kJNIEnvTableSize = sizeof(kJNIEnvTable)/sizeof(kJNIEnvTable[0]);

static const char* lookup_vtable(const VtableEntry* table, size_t n, uint64_t off) {
    for (size_t i = 0; i < n; ++i)
        if (table[i].offset == off) return table[i].name;
    return nullptr;
}

// ---------------------------------------------------------------------------
// Vtable call resolution
//
// Ghidra emits indirect vtable calls as:
//   (**(code **)(*<var> + 0x<hex>))(<args>)
//
// We replace the prefix (**(code **)(*<var> + 0x<hex>)) with (*<var>)-><Func>.
// javavm_var is the name of the JavaVM* variable ("vm" for JNI_OnLoad);
// everything else is treated as JNIEnv*.
// ---------------------------------------------------------------------------

static std::string resolve_vtable_calls(const std::string& text,
                                         const std::string& javavm_var) {
    static const char PREFIX[]   = "(**(code **)(*";
    static const char MID[]      = " + 0x";
    static const size_t PLEN     = sizeof(PREFIX) - 1;
    static const size_t MLEN     = sizeof(MID)    - 1;

    std::string out;
    out.reserve(text.size());
    size_t pos = 0;

    while (pos < text.size()) {
        size_t found = text.find(PREFIX, pos);
        if (found == std::string::npos) {
            out.append(text, pos, std::string::npos);
            break;
        }
        out.append(text, pos, found - pos);

        size_t p = found + PLEN;

        // Read variable name
        size_t var_start = p;
        while (p < text.size() && is_id(text[p])) ++p;
        if (p == var_start) { out += text[found]; pos = found + 1; continue; }
        std::string var(text, var_start, p - var_start);

        // Match " + 0x"
        if (text.compare(p, MLEN, MID) != 0) { out += text[found]; pos = found + 1; continue; }
        p += MLEN;

        // Read hex offset
        size_t hstart = p;
        while (p < text.size() && is_hex(text[p])) ++p;
        if (p == hstart) { out += text[found]; pos = found + 1; continue; }
        uint64_t offset = std::strtoull(std::string(text, hstart, p - hstart).c_str(), nullptr, 16);

        // Expect "))"
        if (p + 1 >= text.size() || text[p] != ')' || text[p+1] != ')') {
            out += text[found]; pos = found + 1; continue;
        }
        p += 2;

        // Look up function name
        bool is_vm = (!javavm_var.empty() && var == javavm_var);
        const char* func = is_vm
            ? lookup_vtable(kJavaVMTable,  kJavaVMTableSize,  offset)
            : lookup_vtable(kJNIEnvTable,  kJNIEnvTableSize,  offset);

        if (func) {
            out += "(*"; out += var; out += ")->"; out += func;
        } else {
            // Unknown offset — keep original text
            out.append(text, found, p - found);
        }
        pos = p;
    }
    return out;
}

// ---------------------------------------------------------------------------
// JNI constant replacement
// Replaces JNI version literals with their #define names.
// Uses identifier-safe boundaries (won't match 0x10006 inside 0x100060).
// ---------------------------------------------------------------------------

struct JniConst { const char* hex; const char* name; };
static const JniConst kJniConsts[] = {
    {"0x10006", "JNI_VERSION_1_6"},
    {"0x10004", "JNI_VERSION_1_4"},
    {"0x10002", "JNI_VERSION_1_2"},
    {"0x10001", "JNI_VERSION_1_1"},
};

static std::string replace_jni_constants(const std::string& src) {
    std::string result = src;
    for (const auto& kc : kJniConsts) {
        const std::string from(kc.hex);
        const std::string to(kc.name);
        const size_t flen = from.size();
        std::string out;
        out.reserve(result.size());
        size_t pos = 0;
        while (pos < result.size()) {
            size_t f = result.find(from, pos);
            if (f == std::string::npos) { out.append(result, pos, std::string::npos); break; }
            // Boundary: not preceded/followed by an identifier char
            bool left_ok  = (f == 0)                || !is_id(result[f - 1]);
            bool right_ok = (f + flen >= result.size()) || !is_id(result[f + flen]);
            if (left_ok && right_ok) {
                out.append(result, pos, f - pos);
                out.append(to);
                pos = f + flen;
            } else {
                out.append(result, pos, f - pos + 1);
                pos = f + 1;
            }
        }
        result = std::move(out);
    }
    return result;
}

// ---------------------------------------------------------------------------
// Local variable type inference
//
// After vtable resolution, lines like:
//   iVar4 = (*piStack_48)->FindClass(piStack_48, "com/Foo");
// let us infer that iVar4 is jclass. We scan the body for these patterns,
// build a {var → jni_type} map, and fix up the Ghidra-generated declaration
// lines at the top of the function (e.g. "int8 iVar4;" → "jclass iVar4;").
//
// Special case: (*vm)->GetEnv(vm, &piStack_48, ...) fills piStack_48 as
// JNIEnv*, so we retype its declaration as "JNIEnv *piStack_48;".
// ---------------------------------------------------------------------------

struct JniReturnType { const char* func; const char* ret_type; };
static const JniReturnType kJniReturnTypes[] = {
    {"FindClass",           "jclass"},
    {"GetObjectClass",      "jclass"},
    {"GetSuperclass",       "jclass"},
    {"GetMethodID",         "jmethodID"},
    {"GetStaticMethodID",   "jmethodID"},
    {"GetFieldID",          "jfieldID"},
    {"GetStaticFieldID",    "jfieldID"},
    {"NewObjectA",          "jobject"},
    {"NewObjectV",          "jobject"},
    {"NewObject",           "jobject"},
    {"NewStringUTF",        "jstring"},
    {"NewString",           "jstring"},
    {"NewGlobalRef",        "jobject"},
    {"NewLocalRef",         "jobject"},
    {"NewWeakGlobalRef",    "jobject"},
    {"AllocObject",         "jobject"},
    {"ExceptionOccurred",   "jthrowable"},
    {"NewDirectByteBuffer", "jobject"},
    {"ToReflectedMethod",   "jobject"},
    {"ToReflectedField",    "jobject"},
    {"PopLocalFrame",       "jobject"},
    {"RegisterNatives",     "jint"},
    {"UnregisterNatives",   "jint"},
    {"GetVersion",          "jint"},
    {"Throw",               "jint"},
    {"ThrowNew",            "jint"},
    {"PushLocalFrame",      "jint"},
    {"MonitorEnter",        "jint"},
    {"MonitorExit",         "jint"},
    {"GetStringLength",     "jsize"},
    {"GetStringUTFLength",  "jsize"},
    {"GetArrayLength",      "jsize"},
    {"IsInstanceOf",        "jboolean"},
    {"IsAssignableFrom",    "jboolean"},
    {"IsSameObject",        "jboolean"},
    {"ExceptionCheck",      "jboolean"},
};
static const size_t kJniReturnTypesCount =
    sizeof(kJniReturnTypes)/sizeof(kJniReturnTypes[0]);

static const char* lookup_jni_return_type(const std::string& func) {
    for (size_t i = 0; i < kJniReturnTypesCount; ++i)
        if (func == kJniReturnTypes[i].func)
            return kJniReturnTypes[i].ret_type;
    return nullptr;
}

// Infer {var_name → jni_type} from assignment lines.
static std::map<std::string,std::string> infer_local_types(
        const std::vector<std::string>& lines) {
    std::map<std::string,std::string> m;

    for (const auto& line : lines) {
        size_t arrow = line.find("->");
        if (arrow == std::string::npos || arrow == 0) continue;
        // Require ')' immediately before '->' (end of vtable dereference)
        if (line[arrow - 1] != ')') continue;

        // Read function name after '->'
        size_t fn_start = arrow + 2;
        size_t fn_end   = fn_start;
        while (fn_end < line.size() &&
               (std::isalnum((unsigned char)line[fn_end]) || line[fn_end]=='_'))
            ++fn_end;
        if (fn_end == fn_start) continue;
        std::string func(line, fn_start, fn_end - fn_start);

        if (fn_end >= line.size() || line[fn_end] != '(') continue;

        // --- Special case: GetEnv output arg ---
        // Pattern: (*vm)->GetEnv(vm, &<var>, ...)
        if (func == "GetEnv") {
            size_t p = fn_end + 1;
            // Skip first arg (vm)
            while (p < line.size() && line[p] != ',' && line[p] != ')') ++p;
            if (p >= line.size() || line[p] != ',') continue;
            ++p;
            while (p < line.size() && line[p] == ' ') ++p;
            if (p >= line.size() || line[p] != '&') continue;
            ++p;
            size_t vs = p;
            while (p < line.size() && (std::isalnum((unsigned char)line[p]) || line[p]=='_')) ++p;
            if (p == vs) continue;
            m[std::string(line, vs, p - vs)] = "JNIEnv *";
            continue;
        }

        const char* ret = lookup_jni_return_type(func);
        if (!ret) continue;

        // Walk backwards from arrow to find `= (`  (the vtable call)
        // Then find the `=` assignment operator and extract LHS variable.
        // The expression to skip backwards over: (* ... )->
        // We just search backwards for '=' preceded by whitespace.
        int64_t eq = static_cast<int64_t>(arrow) - 1;
        // skip whitespace, '*', '(' that make up (*<env>)
        while (eq >= 0 && (line[eq]==' '||line[eq]=='\t'||line[eq]=='*'||line[eq]=='(')) --eq;
        if (eq < 0 || line[eq] != '=') continue;
        --eq;
        while (eq >= 0 && (line[eq]==' '||line[eq]=='\t')) --eq;
        if (eq < 0 || (!std::isalnum((unsigned char)line[eq]) && line[eq]!='_')) continue;

        int64_t ve = eq + 1;
        int64_t vs = ve;
        while (vs > 0 && (std::isalnum((unsigned char)line[vs-1]) || line[vs-1]=='_')) --vs;
        if (vs == ve) continue;
        std::string var(line, static_cast<size_t>(vs), static_cast<size_t>(ve - vs));
        m[var] = ret;
    }
    return m;
}

// Rewrite a declaration line's type if the variable is in type_map.
// Ghidra declaration forms:
//   "  int8 iVar4;"     "  int8 *piStack_48;"    "  xunknown4 xVar3;"
// New type replaces the old type token.  Pointer stars are dropped because
// the JNI types already encode pointer-ness (jclass, JNIEnv *, …).
// 'tm' maps CURRENT var name → new JNI type string.
// 'renamed' maps CURRENT var name → new semantic var name (may equal current).
static std::string fix_decl_line(const std::string& line,
                                   const std::map<std::string,std::string>& tm,
                                   const std::map<std::string,std::string>& renamed,
                                   bool remove_if_collapsed) {
    if (line.empty() || (line[0]!=' ' && line[0]!='\t')) return line;
    size_t p = 0;
    while (p < line.size() && (line[p]==' '||line[p]=='\t')) ++p;
    size_t type_start = p;
    while (p < line.size() && (std::isalnum((unsigned char)line[p])||line[p]=='_')) ++p;
    if (p == type_start) return line;
    while (p < line.size() && (line[p]==' '||line[p]=='\t'||line[p]=='*')) ++p;
    size_t var_start = p;
    while (p < line.size() && (std::isalnum((unsigned char)line[p])||line[p]=='_')) ++p;
    if (p == var_start) return line;
    std::string var(line, var_start, p - var_start);
    size_t q = p;
    while (q < line.size() && (line[q]==' '||line[q]=='\t')) ++q;
    if (q >= line.size() || (line[q]!=';' && line[q]!='[')) return line;

    // Drop declaration entirely if this var will be collapsed into a struct.
    if (remove_if_collapsed && renamed.count(var) && renamed.at(var).empty())
        return "";

    auto type_it = tm.find(var);
    if (type_it == tm.end()) return line;

    // Use renamed var name if available, else keep original.
    auto name_it = renamed.find(var);
    const std::string& new_var = (name_it != renamed.end() && !name_it->second.empty())
                                     ? name_it->second : var;

    std::string leading(line, 0, type_start);
    std::string suffix(line, p, std::string::npos); // ';' onward (after old var name)
    const std::string& nt = type_it->second;
    bool needs_space = !nt.empty() && nt.back() != ' ' && nt.back() != '*';
    return leading + nt + (needs_space ? " " : "") + new_var + suffix;
}

// ---------------------------------------------------------------------------
// Semantic rename assignment
// ---------------------------------------------------------------------------

// Returns true if 'name' appears as a whole identifier in 'code'.
static bool ident_exists(const std::string& code, const std::string& name) {
    const size_t n = name.size();
    size_t pos = 0;
    while (pos < code.size()) {
        size_t f = code.find(name, pos);
        if (f == std::string::npos) return false;
        bool lo = (f == 0)          || !is_id(code[f-1]);
        bool ro = (f+n >= code.size()) || !is_id(code[f+n]);
        if (lo && ro) return true;
        pos = f + 1;
    }
    return false;
}

// Assign semantic names: JNIEnv*→env, jclass→cls, jmethodID→mid, …
// Returns {old_name → new_semantic_name}.  If unchanged, new == old.
static std::map<std::string,std::string> build_rename_map(
        const std::map<std::string,std::string>& tm,
        const std::string& code) {
    std::map<std::string,std::string> rename;
    int cls_n=0, mid_n=0, fid_n=0, obj_n=0, jstr_n=0, exc_n=0;

    auto next_name = [&](const char* base, int& cnt) -> std::string {
        cnt++;
        if (cnt == 1) return base;
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%s%d", base, cnt);
        return buf;
    };

    for (const auto& kv : tm) {
        const std::string& old_name = kv.first;
        const std::string& type     = kv.second;
        std::string new_name;

        if (type == "JNIEnv *") {
            new_name = "env";
        } else if (type == "jclass") {
            new_name = next_name("cls", cls_n);
        } else if (type == "jmethodID") {
            new_name = next_name("mid", mid_n);
        } else if (type == "jfieldID") {
            new_name = next_name("fid", fid_n);
        } else if (type == "jstring") {
            new_name = next_name("jstr", jstr_n);
        } else if (type == "jobject") {
            new_name = next_name("obj", obj_n);
        } else if (type == "jthrowable") {
            new_name = next_name("exc", exc_n);
        } else {
            rename[old_name] = old_name; // no rename for jint/jboolean/jsize
            continue;
        }

        // Avoid clobbering a name that is already used for something else.
        if (new_name != old_name && ident_exists(code, new_name))
            rename[old_name] = old_name;
        else
            rename[old_name] = new_name;
    }
    return rename;
}

// Entry point: infer JNI local types, rename in body and fix declarations.
static std::string resolve_jni_locals(const std::string& code) {
    std::vector<std::string> lines = split_lines(code);
    auto tm = infer_local_types(lines);
    if (tm.empty()) return code;

    // Build semantic rename map and apply renames to the whole body first.
    auto rename = build_rename_map(tm, code);
    std::string result = code;
    for (const auto& kv : rename) {
        if (kv.first != kv.second && !kv.second.empty())
            result = replace_ident(result, kv.first, kv.second);
    }

    // Fix declaration types (variable names in declarations are now renamed).
    // Build a type map keyed by NEW names so fix_decl_line can look them up.
    std::map<std::string,std::string> tm_new;
    std::map<std::string,std::string> rename_new; // new_name → new_name (identity)
    for (const auto& kv : tm) {
        const std::string& new_name = rename.count(kv.first) ? rename.at(kv.first) : kv.first;
        if (!new_name.empty()) {
            tm_new[new_name] = kv.second;
            rename_new[new_name] = new_name;
        }
    }

    std::vector<std::string> lines2 = split_lines(result);
    std::string out;
    out.reserve(result.size());
    for (size_t i = 0; i < lines2.size(); ++i) {
        if (i) out += '\n';
        std::string fixed = fix_decl_line(lines2[i], tm_new, rename_new, false);
        out += fixed;
    }
    return out;
}

// ---------------------------------------------------------------------------
// JNINativeMethod struct collapse
//
// Detects the pattern:
//   xStack_40 = "name";
//   xStack_38 = "signature";
//   xStack_30 = <fnptr>;
//   RegisterNatives(env, cls, &xStack_40, 1);
//
// and replaces it with:
//   JNINativeMethod methods[] = {{"name", "signature", <fnptr>}};
//   RegisterNatives(env, cls, methods, 1);
//
// Ghidra xStack_NN variables use hex suffixes where lower NN = higher memory
// address: sig is at xStack_{N-8} and fnPtr at xStack_{N-16} from the name
// var, because each 8-byte LE decrease in the frame-pointer offset corresponds
// to +8 in the actual array memory layout.
// ---------------------------------------------------------------------------

// Parse the hex numeric suffix from an xStack_NN variable name.
// Returns false if the name doesn't match.
static bool parse_xstack_index(const std::string& name, uint64_t& out) {
    static const char PFX[] = "xStack_";
    static const size_t PLEN = 7;
    if (name.size() <= PLEN) return false;
    if (name.compare(0, PLEN, PFX) != 0) return false;
    const char* p = name.c_str() + PLEN;
    if (!std::isxdigit((unsigned char)*p)) return false;
    char* end;
    out = std::strtoull(p, &end, 16);
    return *end == '\0';
}

// Format an xStack variable name from a hex index.
static std::string xstack_name(uint64_t idx) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "xStack_%llx",
                  (unsigned long long)idx);
    return buf;
}

// Find the LAST assignment `<var> = <value>;` in lines.
// Returns the line index and extracts the value string (trimmed, no semicolon).
static bool find_last_assignment(const std::vector<std::string>& lines,
                                  const std::string& var,
                                  size_t& line_idx_out,
                                  std::string& value_out) {
    const size_t vlen = var.size();
    bool found = false;
    for (size_t i = 0; i < lines.size(); ++i) {
        const std::string& l = lines[i];
        size_t p = 0;
        while (p < l.size() && (l[p]==' '||l[p]=='\t')) ++p;
        if (l.compare(p, vlen, var) != 0) continue;
        p += vlen;
        while (p < l.size() && (l[p]==' '||l[p]=='\t')) ++p;
        if (p >= l.size() || l[p] != '=') continue;
        ++p;
        while (p < l.size() && (l[p]==' '||l[p]=='\t')) ++p;
        // Read value up to ';'
        size_t val_start = p;
        // Find closing ';' at this nesting level
        int depth = 0;
        while (p < l.size()) {
            if (l[p]=='{') ++depth;
            else if (l[p]=='}') --depth;
            else if (l[p]==';' && depth==0) break;
            ++p;
        }
        if (p >= l.size()) continue; // no ';'
        // Trim trailing whitespace from value
        size_t val_end = p;
        while (val_end > val_start && (l[val_end-1]==' '||l[val_end-1]=='\t')) --val_end;
        value_out = std::string(l, val_start, val_end - val_start);
        line_idx_out = i;
        found = true;
    }
    return found;
}

// Find and remove a simple declaration line `<any_type> <var>;`.
static void remove_decl_line(std::vector<std::string>& lines,
                               const std::string& var) {
    const size_t vlen = var.size();
    for (size_t i = 0; i < lines.size(); ++i) {
        const std::string& l = lines[i];
        // Must be an indented line (declaration)
        if (l.empty() || (l[0]!=' ' && l[0]!='\t')) continue;
        size_t p = 0;
        while (p < l.size() && (l[p]==' '||l[p]=='\t')) ++p;
        // Skip type token + spaces/stars
        while (p < l.size() && (std::isalnum((unsigned char)l[p])||l[p]=='_')) ++p;
        while (p < l.size() && (l[p]==' '||l[p]=='\t'||l[p]=='*')) ++p;
        if (l.compare(p, vlen, var) != 0) continue;
        p += vlen;
        size_t q = p;
        while (q < l.size() && (l[q]==' '||l[q]=='\t')) ++q;
        if (q >= l.size() || l[q] != ';') continue;
        lines[i] = ""; // blank the line (will be stripped on join)
    }
}

static std::string collapse_native_methods(const std::string& code) {
    // Find `->RegisterNatives(` in the code.
    const char REGNATIVES[] = "->RegisterNatives(";
    const size_t RGNLEN     = sizeof(REGNATIVES) - 1;

    std::string result = code;

    // We may have multiple RegisterNatives calls; loop until no more matches.
    for (;;) {
        size_t rg = result.find(REGNATIVES);
        if (rg == std::string::npos) break;

        // Parse RegisterNatives args: (env, cls, &struct_var, count)
        size_t arg_start = rg + RGNLEN;

        // Skip first two args (env, cls) — just scan past them
        size_t p = arg_start;
        // Arg 0 (env)
        { int d=0;
          while (p < result.size() && !(d==0 && result[p]==',')) {
              if(result[p]=='(') ++d; else if(result[p]==')') { if(d--==0) break; } ++p; }
          if (p >= result.size() || result[p]!=',') break; ++p;
          while (p < result.size() && result[p]==' ') ++p; }
        // Arg 1 (cls)
        { int d=0;
          while (p < result.size() && !(d==0 && result[p]==',')) {
              if(result[p]=='(') ++d; else if(result[p]==')') { if(d--==0) break; } ++p; }
          if (p >= result.size() || result[p]!=',') break; ++p;
          while (p < result.size() && result[p]==' ') ++p; }

        // Arg 2: &struct_var
        if (p >= result.size() || result[p] != '&') break;
        ++p;
        size_t sv_start = p;
        while (p < result.size() && (std::isalnum((unsigned char)result[p])||result[p]=='_')) ++p;
        std::string struct_var(result, sv_start, p - sv_start);

        uint64_t base_idx;
        if (!parse_xstack_index(struct_var, base_idx)) break;

        // Arg 3: count literal (skip comma + spaces)
        while (p < result.size() && (result[p]==' '||result[p]==',')) ++p;
        size_t count_start = p;
        while (p < result.size() && std::isdigit((unsigned char)result[p])) ++p;
        if (p == count_start) break; // no count literal
        int count = std::atoi(std::string(result, count_start, p - count_start).c_str());
        if (count <= 0 || count > 64) break; // sanity check

        // Collect JNINativeMethod fields for each element.
        struct NMEntry { std::string name_val, sig_val, fnptr_val; };
        std::vector<NMEntry> entries;
        bool ok = true;

        // Gather lines for manipulation
        std::vector<std::string> lines = split_lines(result);
        std::vector<size_t> lines_to_blank; // assignment lines to remove

        for (int i = 0; i < count && ok; ++i) {
            // Element i:
            // name_var   at base_idx + i*0x18  (= base + 0 for i=0)
            // sig_var    at base_idx - 8 + i*0x18... wait — need the right formula.
            // From the observed pattern (xStack_40=name, xStack_38=sig, xStack_30=fnPtr):
            // As i increases, all three indices also increase (less negative offset).
            // sig_idx   = name_idx - 8
            // fnptr_idx = name_idx - 16
            // elem i name_idx = base_idx - i * 0x18  (decreasing for i>0? No...)
            // Actually elem 0 name = base_idx; subsequent elements have LARGER base_idx
            // because they are at higher absolute addresses → smaller FP-relative offsets.
            // Wait: higher absolute addr → smaller xStack index.
            // For i=0: name at base_idx (e.g., 0x40)
            // For i=1: name at base_idx - 0x18 (e.g., 0x28)  ← one struct-size down the stack
            uint64_t name_idx   = base_idx - (uint64_t)i * 0x18;
            uint64_t sig_idx_v  = name_idx - 8;
            uint64_t fnptr_idx  = name_idx - 16;

            std::string nv = xstack_name(name_idx);
            std::string sv = xstack_name(sig_idx_v);
            std::string fv = xstack_name(fnptr_idx);

            NMEntry e;
            size_t li;
            if (!find_last_assignment(lines, nv, li, e.name_val))  { ok=false; break; }
            lines_to_blank.push_back(li);
            if (!find_last_assignment(lines, sv, li, e.sig_val))   { ok=false; break; }
            lines_to_blank.push_back(li);
            if (!find_last_assignment(lines, fv, li, e.fnptr_val)) { ok=false; break; }
            lines_to_blank.push_back(li);

            entries.push_back(e);
        }
        if (!ok || entries.empty()) break;

        // All found — blank the assignment lines
        for (size_t li : lines_to_blank) lines[li] = "";

        // Remove xStack declarations from the header block
        for (int i = 0; i < count; ++i) {
            uint64_t name_idx  = base_idx - (uint64_t)i * 0x18;
            remove_decl_line(lines, xstack_name(name_idx));
            remove_decl_line(lines, xstack_name(name_idx - 8));
            remove_decl_line(lines, xstack_name(name_idx - 16));
        }

        // Build JNINativeMethod initializer string.
        // Determine indent from the RegisterNatives line.
        size_t rg_line = std::string::npos;
        for (size_t i = 0; i < lines.size(); ++i)
            if (lines[i].find("->RegisterNatives(") != std::string::npos)
                { rg_line = i; break; }

        std::string indent = "    ";
        if (rg_line != std::string::npos) {
            size_t qi = 0;
            while (qi < lines[rg_line].size() &&
                   (lines[rg_line][qi]==' '||lines[rg_line][qi]=='\t')) ++qi;
            indent = std::string(lines[rg_line], 0, qi);
        }

        // Generate:  JNINativeMethod methods[] = { {"n","s",fn}, ... };
        std::string decl = indent + "JNINativeMethod methods[] = {";
        for (size_t i = 0; i < entries.size(); ++i) {
            if (i) decl += ",";
            decl += "{" + entries[i].name_val + ", " +
                          entries[i].sig_val  + ", " +
                          entries[i].fnptr_val + "}";
        }
        decl += "};";

        // Insert the decl just before the RegisterNatives line
        if (rg_line != std::string::npos)
            lines.insert(lines.begin() + (ptrdiff_t)rg_line, decl);
        // rg_line is now one past the decl (since we inserted above it)

        // Rewrite the RegisterNatives call: replace `&struct_var, count_literal`
        // with `methods, count`.
        char count_str[16];
        std::snprintf(count_str, sizeof(count_str), "%d", count);
        // Rebuild the result from lines, then do a targeted string replace.
        result = join_lines(lines);

        // Replace `&<struct_var>, <count_literal>)` with `methods, <count>)`
        // in the reconstructed text.
        std::string old_ref = "&" + struct_var + ", " + count_str + ")";
        std::string new_ref = std::string("methods, ") + count_str + ")";
        {
            size_t pos = result.find(old_ref);
            if (pos != std::string::npos)
                result.replace(pos, old_ref.size(), new_ref);
        }

        // Remove consecutive blank lines (left by blanked assignment lines)
        {
            std::string cleaned;
            cleaned.reserve(result.size());
            bool prev_blank = false;
            for (char c : result) {
                if (c == '\n') {
                    if (!prev_blank) cleaned += c;
                    prev_blank = true;
                } else {
                    prev_blank = false;
                    cleaned += c;
                }
            }
            result = std::move(cleaned);
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// JNI kind detection
// ---------------------------------------------------------------------------

enum class JniKind { NONE, ON_LOAD, ON_UNLOAD, JAVA_METHOD };

static JniKind detect_kind(const std::string& name) {
    if (name == "JNI_OnLoad")   return JniKind::ON_LOAD;
    if (name == "JNI_OnUnload") return JniKind::ON_UNLOAD;
    if (name.size() > 5 &&
        name[0]=='J' && name[1]=='a' && name[2]=='v' &&
        name[3]=='a' && name[4]=='_')
        return JniKind::JAVA_METHOD;
    return JniKind::NONE;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// Cache version tag — prepended to stored pseudocode so stale entries
// are auto-invalidated.  Must NOT contain characters in Ghidra's C output.
const char* JNI_ANNOTATOR_CACHE_TAG = "\x01PEEK_ANN_V5\x01\n";

std::string jni_annotate(const std::string& func_name,
                          const std::string& pseudocode) {
    JniKind kind = detect_kind(func_name);
    if (kind == JniKind::NONE) return pseudocode;

    std::vector<std::string> lines = split_lines(pseudocode);

    // ---- 1. Fix the function signature line --------------------------------
    size_t sig_idx = find_sig_line(lines, func_name);
    if (sig_idx < lines.size()) {
        std::string& sig = lines[sig_idx];
        if (kind == JniKind::ON_LOAD || kind == JniKind::ON_UNLOAD) {
            size_t indent_end = sig.find_first_not_of(" \t");
            std::string indent = (indent_end != std::string::npos)
                                     ? sig.substr(0, indent_end) : "";
            size_t close = sig.rfind(')');
            std::string suffix = (close != std::string::npos)
                                     ? sig.substr(close + 1) : "";
            const char* ret = (kind == JniKind::ON_LOAD) ? "jint" : "void";
            const char* nm  = (kind == JniKind::ON_LOAD) ? "JNI_OnLoad" : "JNI_OnUnload";
            sig = indent + ret + " " + nm + "(JavaVM *vm, void *reserved)" + suffix;
        } else {
            sig = replace_param_in_sig(sig, "param_1", "JNIEnv *env");
            sig = replace_param_in_sig(sig, "param_2", "jobject thiz");
        }
    }

    // ---- 2. Rename param identifiers throughout the body -------------------
    std::string result = join_lines(lines);
    if (kind == JniKind::ON_LOAD || kind == JniKind::ON_UNLOAD) {
        result = replace_ident(result, "param_1", "vm");
        result = replace_ident(result, "param_2", "reserved");
    } else {
        result = replace_ident(result, "param_1", "env");
        result = replace_ident(result, "param_2", "thiz");
    }

    // ---- 3. Resolve vtable calls -------------------------------------------
    const std::string javavm_var =
        (kind == JniKind::ON_LOAD || kind == JniKind::ON_UNLOAD) ? "vm" : "";
    result = resolve_vtable_calls(result, javavm_var);

    // ---- 4. Replace JNI version constants ----------------------------------
    result = replace_jni_constants(result);

    // ---- 5. Infer local variable types, rename in body, fix declarations ---
    // Infers types from JNI call-site patterns (FindClass→jclass, etc.),
    // renames variables to semantic names (piStack_48→env, iVar4→cls, …)
    // throughout the whole body, and updates the declaration types.
    result = resolve_jni_locals(result);

    // ---- 6. Collapse xStack JNINativeMethod patterns -----------------------
    // Detects RegisterNatives calls using stack-local struct fields and
    // rewrites them to a proper JNINativeMethod array declaration.
    result = collapse_native_methods(result);

    return result;
}
