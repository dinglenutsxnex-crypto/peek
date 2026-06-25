#include "jni_annotator.h"

#include <cctype>
#include <sstream>
#include <vector>

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// Returns true if c is a C identifier character.
static bool is_id(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
}

// Whole-word (C identifier boundary) string replacement.
// Replaces every occurrence of `from` that is not part of a longer identifier.
// e.g. replace_ident(text, "param_1", "env") won't touch "param_10".
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
        if (f == std::string::npos) {
            out.append(src, pos, std::string::npos);
            break;
        }
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

// Within a single signature line, find the token sequence that declares
// `param_tag` (e.g. "int8 *param_1") and replace the whole type+name token
// with `replacement` (e.g. "JNIEnv *env").
//
// It walks backward from the `param_tag` occurrence to find where the type
// declaration starts (stopping at '(', ',' or start-of-string), then splices
// in the replacement string.
//
// Returns `sig` unchanged if `param_tag` is not found as a whole word.
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

        // Walk left from `f` to find the start of the type declaration.
        // Skip whitespace and '*' immediately before the param name.
        ssize_t scan = static_cast<ssize_t>(f) - 1;
        while (scan >= 0 && (sig[scan] == ' ' || sig[scan] == '\t' || sig[scan] == '*'))
            --scan;
        // Skip the type keyword (e.g. "int8", "undefined8", "long").
        while (scan >= 0 && is_id(sig[scan]))
            --scan;
        // Skip any whitespace between a prior type qualifier and this one
        // (handles "unsigned int *param_1" style, two words in the type).
        while (scan >= 0 && (sig[scan] == ' ' || sig[scan] == '\t'))
            --scan;
        // If there's another identifier word before (e.g. "unsigned" in
        // "unsigned int"), include it.
        if (scan >= 0 && is_id(sig[scan])) {
            while (scan >= 0 && is_id(sig[scan])) --scan;
            while (scan >= 0 && (sig[scan] == ' ' || sig[scan] == '\t')) --scan;
        }
        // `scan` now points to '(', ',', or is -1.
        // The type declaration starts at scan+1.
        size_t type_start = static_cast<size_t>(scan + 1);

        // Build the prefix up to (but not including) the type declaration.
        // Trim trailing whitespace so that "env,  undefined8" doesn't leave
        // a double-space gap, then re-add exactly one space when the
        // separator is ',' (no extra space needed after '(').
        std::string prefix(sig, 0, type_start);
        while (!prefix.empty() &&
               (prefix.back() == ' ' || prefix.back() == '\t'))
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

// Split `text` into lines (preserves empty lines).
static std::vector<std::string> split_lines(const std::string& text) {
    std::vector<std::string> lines;
    std::istringstream ss(text);
    std::string line;
    while (std::getline(ss, line)) lines.push_back(line);
    return lines;
}

// Join lines back with newlines.
static std::string join_lines(const std::vector<std::string>& lines) {
    std::string out;
    for (size_t i = 0; i < lines.size(); ++i) {
        out += lines[i];
        if (i + 1 < lines.size()) out += '\n';
    }
    return out;
}

// Find the index of the line that contains `funcname` immediately followed
// (after optional spaces) by '('.  The name must be a whole word (not part
// of a longer identifier).  Returns lines.size() if not found.
static size_t find_sig_line(const std::vector<std::string>& lines,
                              const std::string& funcname) {
    const size_t flen = funcname.size();
    for (size_t i = 0; i < lines.size(); ++i) {
        const std::string& l = lines[i];
        size_t f = 0;
        while (f < l.size()) {
            size_t found = l.find(funcname, f);
            if (found == std::string::npos) break;

            bool left_ok  = (found == 0)               || !is_id(l[found - 1]);
            bool right_ok = (found + flen >= l.size())  || !is_id(l[found + flen]);
            if (left_ok && right_ok) {
                // Verify '(' follows.
                size_t j = found + flen;
                while (j < l.size() && l[j] == ' ') ++j;
                if (j < l.size() && l[j] == '(') return i;
            }
            f = found + 1;
        }
    }
    return lines.size(); // not found
}

// ---------------------------------------------------------------------------
// JNI kind detection
// ---------------------------------------------------------------------------

enum class JniKind { NONE, ON_LOAD, ON_UNLOAD, JAVA_METHOD };

static JniKind detect_kind(const std::string& name) {
    if (name == "JNI_OnLoad")   return JniKind::ON_LOAD;
    if (name == "JNI_OnUnload") return JniKind::ON_UNLOAD;
    if (name.size() > 5 && name[0]=='J' && name[1]=='a' && name[2]=='v' &&
        name[3]=='a' && name[4]=='_')
        return JniKind::JAVA_METHOD;
    return JniKind::NONE;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

std::string jni_annotate(const std::string& func_name,
                          const std::string& pseudocode) {
    JniKind kind = detect_kind(func_name);
    if (kind == JniKind::NONE) return pseudocode;

    std::vector<std::string> lines = split_lines(pseudocode);

    // ---- Fix the function signature line --------------------------------

    size_t sig_idx = find_sig_line(lines, func_name);
    if (sig_idx < lines.size()) {
        std::string& sig = lines[sig_idx];

        if (kind == JniKind::ON_LOAD || kind == JniKind::ON_UNLOAD) {
            // We know the canonical JNI signature exactly, so replace the
            // entire signature.  Preserve leading whitespace and any trailing
            // content after the closing ')' (e.g. Ghidra sometimes puts the
            // opening '{' on the same line in some output modes).
            size_t indent_end = sig.find_first_not_of(" \t");
            std::string indent = (indent_end != std::string::npos)
                                     ? sig.substr(0, indent_end)
                                     : "";
            size_t close = sig.rfind(')');
            std::string suffix = (close != std::string::npos)
                                     ? sig.substr(close + 1)
                                     : "";
            const char* ret = (kind == JniKind::ON_LOAD) ? "jint" : "void";
            const char* nm  = (kind == JniKind::ON_LOAD) ? "JNI_OnLoad"
                                                          : "JNI_OnUnload";
            sig = indent + ret + " " + nm +
                  "(JavaVM *vm, void *reserved)" + suffix;
        } else {
            // Java_* — replace only param_1 and param_2 type+name tokens.
            // Return type and any additional params are preserved verbatim.
            sig = replace_param_in_sig(sig, "param_1", "JNIEnv *env");
            sig = replace_param_in_sig(sig, "param_2", "jobject thiz");
        }
    }

    // ---- Rename param identifiers throughout the whole text --------------
    // Do this AFTER rebuilding the sig line so the sig replacement above is
    // already correct and the rename pass only touches the body.

    std::string result = join_lines(lines);

    if (kind == JniKind::ON_LOAD || kind == JniKind::ON_UNLOAD) {
        result = replace_ident(result, "param_1", "vm");
        result = replace_ident(result, "param_2", "reserved");
    } else {
        result = replace_ident(result, "param_1", "env");
        result = replace_ident(result, "param_2", "thiz");
    }

    // ---- Prepend a brief annotation notice -------------------------------
    // Placed before the first non-comment, non-blank content so it appears
    // at the top of the displayed pseudocode.
    result = "/* [PEEK] JNI annotations applied */\n" + result;

    return result;
}
