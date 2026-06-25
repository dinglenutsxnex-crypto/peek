#include "jni_annotator.h"

#include <cctype>
#include <cstdlib>   // strtoull
#include <cstring>   // strlen
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
// (from before vtable/string resolution was added) are auto-invalidated.
// Must NOT contain characters that appear in Ghidra's C output.
const char* JNI_ANNOTATOR_CACHE_TAG = "\x01PEEK_ANN_V3\x01\n";

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
    // For JNI_OnLoad/Unload: "vm" is JavaVM*, everything else is JNIEnv*.
    // For Java_*: no JavaVM calls expected; all vtable calls are JNIEnv*.
    const std::string javavm_var =
        (kind == JniKind::ON_LOAD || kind == JniKind::ON_UNLOAD) ? "vm" : "";
    result = resolve_vtable_calls(result, javavm_var);

    // ---- 4. Replace JNI version constants ----------------------------------
    result = replace_jni_constants(result);

    return result;
}
