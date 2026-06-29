#include "algo_detector.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <set>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static bool has(const std::string& code, const char* needle) {
    return code.find(needle) != std::string::npos;
}

// Case-insensitive substring search.
static bool ihas(const std::string& code, const char* needle) {
    std::string lo = code;
    std::transform(lo.begin(), lo.end(), lo.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    std::string ndl(needle);
    std::transform(ndl.begin(), ndl.end(), ndl.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return lo.find(ndl) != std::string::npos;
}

// Count non-overlapping occurrences of needle in code.
static int count_occurrences(const std::string& code, const char* needle) {
    int n = 0;
    size_t pos = 0;
    size_t nlen = std::strlen(needle);
    while ((pos = code.find(needle, pos)) != std::string::npos) {
        ++n;
        pos += nlen;
    }
    return n;
}

// ---------------------------------------------------------------------------
// XOR / obfuscation detections
// ---------------------------------------------------------------------------

// XOR loop — array element XORed with a key inside a counted loop.
// Requires XOR and an indexed dereference to appear on the SAME line (not just
// anywhere in the function), preventing false positives where a loop and XOR
// ops happen to coexist in separate if-blocks.
static void detect_xor_loop(const std::string& code, std::vector<AlgoHit>& hits) {
    bool has_loop = has(code, "do {") || has(code, "while (") || has(code, "for (");
    if (!has_loop) return;
    // Walk line-by-line: a hit requires XOR + indexed memory + assignment on
    // one line.  Indexed memory = pointer dereference *(  or  array [ access.
    size_t line_start = 0;
    while (line_start < code.size()) {
        size_t line_end = code.find('\n', line_start);
        if (line_end == std::string::npos) line_end = code.size();
        if (line_end > line_start) {
            const char* ls = code.c_str() + line_start;
            size_t     len = line_end - line_start;
            auto lhas = [&](const char* n) {
                return std::string(ls, len).find(n) != std::string::npos;
            };
            bool xor_op  = lhas("^");
            bool indexed = lhas("*(") || lhas("[");
            bool assign  = lhas("=");
            if (xor_op && indexed && assign) {
                // Crypto XOR modifies data in place: data[i] = data[i] ^ key
                // Exclude accumulator patterns: local_var = local_var ^ data[i]
                // by checking that the assignment target itself contains a dereference.
                std::string lstr(ls, len);
                size_t eq_pos = lstr.find('=');
                if (eq_pos != std::string::npos) {
                    std::string target = lstr.substr(0, eq_pos);
                    if (target.find("*(") != std::string::npos || target.find('[') != std::string::npos) {
                        hits.push_back({"XOR loop"});
                        return;
                    }
                }
            }
        }
        line_start = line_end + 1;
    }
}

// Single-byte XOR key — constant is a repeated byte (e.g. 0x2e2e2e2e2e2e2e2e).
// Characteristic of simplest XOR ciphers / compile-time string obfuscators.
// Exclude 0xffffffff (all-ones / ~0) which is a common bit-mask, not a cipher key.
static void detect_single_byte_xor_key(const std::string& code,
                                        std::vector<AlgoHit>& hits) {
    // Find every "^ 0x" occurrence, extract the hex literal, and check if
    // all nibble pairs (bytes) are identical.
    size_t pos = 0;
    while ((pos = code.find("^ 0x", pos)) != std::string::npos) {
        pos += 4; // skip "^ 0x"
        size_t hex_start = pos;
        while (pos < code.size() && std::isxdigit((unsigned char)code[pos])) ++pos;
        size_t hex_len = pos - hex_start;
        // Only care about multi-byte constants (4+ hex digits = 2+ bytes)
        if (hex_len < 4 || hex_len % 2 != 0) continue;
        // Check every byte pair equals the first byte pair
        bool repeated = true;
        std::string first_byte(code, hex_start, 2);
        for (size_t i = 2; i < hex_len; i += 2) {
            if (code.compare(hex_start + i, 2, first_byte) != 0) {
                repeated = false;
                break;
            }
        }
        if (repeated) {
            // Skip 0xffffffff / 0xFF — common bit-mask, not a cipher key
            if (first_byte == "ff" || first_byte == "FF") {
                // Only skip if ALL bytes are 0xFF (i.e. it's 0xFFFF... / ~0)
                bool all_ff = true;
                for (size_t i = 0; i < hex_len; i += 2) {
                    if (code.compare(hex_start + i, 2, "ff") != 0 &&
                        code.compare(hex_start + i, 2, "FF") != 0) {
                        all_ff = false;
                        break;
                    }
                }
                if (all_ff) continue;
            }
            hits.push_back({"Single-byte XOR key (0x" + first_byte + ")"});
            return;
        }
    }
}

// ay::obfuscate — compile-time XOR string obfuscation library by Adam Yaxley.
// Detects mangled C++ names from the ay namespace / OBFUSCATE_data template.
static void detect_ay_obfuscate(const std::string& code, std::vector<AlgoHit>& hits) {
    // Mangled destructor:  _ZN2ay14OBFUSCATE_dataI...ED2Ev  or  ED1Ev
    // Mangled decrypt:     _ZN2ay14OBFUSCATE_dataI...E7decryptEv
    if (has(code, "_ZN2ay") || has(code, "OBFUSCATE_data")) {
        hits.push_back({"ay::obfuscate (compile-time XOR string obfuscation)"});
        return;
    }
    // Also catches cases where the demangler ran and left the C++ name
    if (has(code, "ay::OBFUSCATE") || has(code, "ay::obfuscate")) {
        hits.push_back({"ay::obfuscate (compile-time XOR string obfuscation)"});
    }
}

// Rolling XOR — key state mutates every iteration via rotation or feedback.
// Strong signal: bit rotation (>> N | << M) combined with XOR in a loop,
// AND the XOR must appear on a line that also writes to indexed memory.
//
// MD5 and SHA-1/256 both use left/right shifts + XOR in loops for their
// round functions, so we must exclude them explicitly before checking
// the rotation pattern to avoid false positives.
static void detect_rolling_xor(const std::string& code, std::vector<AlgoHit>& hits) {
    // Bail if MD5 T-table constants are present.
    if (has(code, "0xd76aa478") || ihas(code, "0xd76aa478")) return;
    if (has(code, "0xe8c7b756") || ihas(code, "0xe8c7b756")) return;
    // Bail if SHA-256 round constants are present.
    if (has(code, "0x428a2f98") || ihas(code, "0x428a2f98")) return;
    if (has(code, "0x71374491") || ihas(code, "0x71374491")) return;
    // Bail if SHA-1 init/round constants are present.
    if (has(code, "0x67452301") || ihas(code, "0x67452301")) return;
    if (has(code, "0x5a827999") || ihas(code, "0x5a827999")) return;
    if (has(code, "0x6ed9eba1") || ihas(code, "0x6ed9eba1")) return;
    // Bail if AES S-box constants are present.
    if (has(code, "0x63") && has(code, "0x7c") && has(code, "0x77") && has(code, "0x7b")) return;

    bool has_loop = has(code, "do {") || has(code, "while (") || has(code, "for (");
    if (!has_loop) return;

    bool has_right_shift = has(code, ">> ") || has(code, ">>");
    bool has_left_shift  = has(code, "<< ") || has(code, "<<");
    if (!has_right_shift || !has_left_shift) return;
    if (count_occurrences(code, "^") < 2) return;

    // Require XOR on a line that also touches indexed memory.
    // This distinguishes a cipher (XOR into buf[i]) from a hash
    // round function (XOR between scalar working variables).
    bool xor_on_indexed_line = false;
    size_t line_start = 0;
    while (line_start < code.size() && !xor_on_indexed_line) {
        size_t line_end = code.find('\n', line_start);
        if (line_end == std::string::npos) line_end = code.size();
        if (line_end > line_start) {
            const std::string line(code.c_str() + line_start, line_end - line_start);
            if (line.find('^') != std::string::npos &&
                (line.find("*(") != std::string::npos || line.find('[') != std::string::npos)) {
                xor_on_indexed_line = true;
            }
        }
        line_start = line_end + 1;
    }
    if (!xor_on_indexed_line) return;

    hits.push_back({"Rolling XOR cipher"});
}

// XOR with a fixed constant repeated across iterations.
// Signal: multiple XOR-with-hex-literal lines that also touch indexed memory.
//
// The naive "^ 0x appears twice" rule fires constantly on SHA/MD5/AES because
// their round functions XOR 32-bit constants into scalar registers. Requiring
// the XOR to be on the SAME LINE as indexed memory restricts the hit to genuine
// cipher patterns (data[i] ^= 0xNN) and filters out hash/round-function noise.
static void detect_xor_constant(const std::string& code, std::vector<AlgoHit>& hits) {
    // Bail on known hash/cipher constants that legitimately produce many ^ 0x lines.
    if (has(code, "0xd76aa478") || ihas(code, "0xd76aa478")) return;  // MD5
    if (has(code, "0xe8c7b756") || ihas(code, "0xe8c7b756")) return;  // MD5
    if (has(code, "0x428a2f98") || ihas(code, "0x428a2f98")) return;  // SHA-256
    if (has(code, "0x67452301") || ihas(code, "0x67452301")) return;  // SHA-1
    if (has(code, "0x5a827999") || ihas(code, "0x5a827999")) return;  // SHA-1 round
    if (has(code, "0x9e3779b9") || ihas(code, "0x9e3779b9")) return;  // TEA

    // Count lines that have both "^ 0x" and an indexed memory access.
    int matched = 0;
    size_t line_start = 0;
    while (line_start < code.size()) {
        size_t line_end = code.find('\n', line_start);
        if (line_end == std::string::npos) line_end = code.size();
        if (line_end > line_start) {
            const std::string line(code.c_str() + line_start, line_end - line_start);
            if (line.find("^ 0x") != std::string::npos &&
                (line.find("*(") != std::string::npos || line.find('[') != std::string::npos)) {
                ++matched;
            }
        }
        line_start = line_end + 1;
    }
    if (matched >= 2) hits.push_back({"XOR with constant"});
}

// ---------------------------------------------------------------------------
// AES detections
// ---------------------------------------------------------------------------

// AES S-box — the substitution box starts 0x63, 0x7c, 0x77, 0x7b, 0xf2.
// These five consecutive bytes in that order are essentially unique to AES.
static void detect_aes_sbox(const std::string& code, std::vector<AlgoHit>& hits) {
    // Look for the S-box opening sequence as hex literals in an array
    if (has(code, "0x63") && has(code, "0x7c") && has(code, "0x77") &&
        has(code, "0x7b") && has(code, "0xf2")) {
        hits.push_back({"AES S-box"});
        return;
    }
    // Inverse S-box starts 0x52, 0x09, 0x6a, 0xd5, 0x30
    if (has(code, "0x52") && has(code, "0x09") && has(code, "0x6a") &&
        has(code, "0xd5") && has(code, "0x30")) {
        hits.push_back({"AES inverse S-box"});
    }
}

// AES Rcon — key expansion round constants.
// The 10 Rcon word values (big-endian) used in AES-128 key schedule:
// 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000 ...
// In pseudocode these appear as 32-bit hex literals.
static void detect_aes_rcon(const std::string& code, std::vector<AlgoHit>& hits) {
    int rcon_hits = 0;
    if (has(code, "0x1000000"))  ++rcon_hits;
    if (has(code, "0x2000000"))  ++rcon_hits;
    if (has(code, "0x4000000"))  ++rcon_hits;
    if (has(code, "0x8000000"))  ++rcon_hits;
    if (has(code, "0x10000000")) ++rcon_hits;
    if (rcon_hits >= 2) hits.push_back({"AES key schedule (Rcon)"});
}

// AES-NI intrinsics and named AES API calls.
static void detect_aes_named(const std::string& code, std::vector<AlgoHit>& hits) {
    // AES-NI
    if (has(code, "_mm_aesenc_si128") || has(code, "_mm_aesdec_si128") ||
        has(code, "_mm_aesenclast")   || has(code, "_mm_aesdeclast")   ||
        has(code, "_mm_aeskeygenassist")) {
        hits.push_back({"AES-NI"});
        return;
    }
    // OpenSSL / BoringSSL / mbedTLS / Nettle
    if (ihas(code, "AES_encrypt")     || ihas(code, "AES_decrypt")     ||
        ihas(code, "AES_set_encrypt") || ihas(code, "AES_set_decrypt") ||
        ihas(code, "AES_cbc_encrypt") || ihas(code, "AES_cbc_decrypt") ||
        ihas(code, "AES_ecb_encrypt") ||
        ihas(code, "aes_encrypt")     || ihas(code, "aes_decrypt")     ||
        ihas(code, "EVP_aes_")        ||
        ihas(code, "mbedtls_aes_")    ||
        ihas(code, "nettle_aes")) {
        hits.push_back({"AES (library call)"});
    }
}

// AES key schedule / key detection.
// Signals beyond Rcon (already detected separately):
//   - ARM64 hardware AES instructions visible as mnemonics in pseudocode
//   - SubWord / RotWord helper names from a pure-SW key expansion
//   - Key-size constants 16 / 24 / 32 appearing alongside a "key" token
//   - Android Keystore key-generation APIs
static void detect_aes_key(const std::string& code, std::vector<AlgoHit>& hits) {
    // ARM64 hardware AES — Ghidra may emit instruction mnemonics directly
    // when it cannot lift them to intrinsics.
    if (has(code, "AESE") || has(code, "AESD") ||
        has(code, "AESMC") || has(code, "AESIMC") ||
        has(code, "aese") || has(code, "aesd") ||
        has(code, "aesmc") || has(code, "aesimc")) {
        hits.push_back({"AES (ARM64 hardware instruction)"});
        return;
    }
    // Pure-SW key schedule: SubWord / RotWord helpers.
    if (ihas(code, "SubWord") || ihas(code, "RotWord") ||
        ihas(code, "subword") || ihas(code, "rotword") ||
        ihas(code, "sub_word") || ihas(code, "rot_word")) {
        hits.push_back({"AES key schedule (SubWord/RotWord)"});
        return;
    }
    // Key-size branch: code checks for 16, 24, and 32 AND mentions "key".
    // Covers the switch/if-else that selects AES-128/192/256.
    bool has_key_ctx = ihas(code, "key") || ihas(code, "nk") ||
                       ihas(code, "key_len") || ihas(code, "keylen") ||
                       ihas(code, "key_size") || ihas(code, "keysize");
    if (has_key_ctx) {
        bool has_128 = has(code, "0x10") || has(code, " 16 ") || has(code, "=16") ||
                       has(code, "==16") || has(code, "== 16");
        bool has_192 = has(code, "0x18") || has(code, " 24 ") || has(code, "=24") ||
                       has(code, "==24") || has(code, "== 24");
        bool has_256 = has(code, "0x20") || has(code, " 32 ") || has(code, "=32") ||
                       has(code, "==32") || has(code, "== 32");
        if (has_128 && has_256) {
            hits.push_back({"AES key size selection (128/192/256-bit)"});
            return;
        }
        // Single key size with round-count constant (10 / 12 / 14 rounds)
        int round_hits = 0;
        if (has(code, "0xa") || has(code, "== 10") || has(code, "==10")) ++round_hits;
        if (has(code, "0xc") || has(code, "== 12") || has(code, "==12")) ++round_hits;
        if (has(code, "0xe") || has(code, "== 14") || has(code, "==14")) ++round_hits;
        if (round_hits >= 2 && (has_128 || has_192 || has_256)) {
            hits.push_back({"AES key schedule (round count)"});
            return;
        }
    }
    // Android Keystore key-generation
    if (ihas(code, "AndroidKeyStore")   || ihas(code, "KeyGenerator")       ||
        ihas(code, "SecretKeyFactory")  || ihas(code, "KeyStore.getInstance") ||
        ihas(code, "KeyGenParameterSpec") || ihas(code, "android.security.keystore")) {
        hits.push_back({"AES key via Android Keystore"});
    }
}

// ---------------------------------------------------------------------------
// SHA family detections
// ---------------------------------------------------------------------------

// SHA-256 — first two round constants are globally unique to SHA-256.
// K[0]=0x428a2f98, K[1]=0x71374491
static void detect_sha256(const std::string& code, std::vector<AlgoHit>& hits) {
    if (has(code, "0x428a2f98") || has(code, "0x428A2F98")) {
        hits.push_back({"SHA-256"});
        return;
    }
    if (has(code, "0x71374491") && has(code, "0xb5c0fbcf")) {
        hits.push_back({"SHA-256"});
    }
}

// SHA-1 — initialisation constants + at least one round constant.
// H0=0x67452301, H1=0xEFCDAB89, H2=0x98BADCFE, H3=0x10325476, H4=0xC3D2E1F0
// Round: K1=0x5A827999, K2=0x6ED9EBA1, K3=0x8F1BBCDC, K4=0xCA62C1D6
static void detect_sha1(const std::string& code, std::vector<AlgoHit>& hits) {
    bool init = (has(code, "0x67452301") || ihas(code, "0x67452301")) &&
                (has(code, "0xefcdab89") || ihas(code, "0xefcdab89"));
    if (init) { hits.push_back({"SHA-1"}); return; }
    // Round constants alone are sufficient
    int rk = 0;
    if (has(code, "0x5a827999") || ihas(code, "0x5a827999")) ++rk;
    if (has(code, "0x6ed9eba1") || ihas(code, "0x6ed9eba1")) ++rk;
    if (has(code, "0x8f1bbcdc") || ihas(code, "0x8f1bbcdc")) ++rk;
    if (has(code, "0xca62c1d6") || ihas(code, "0xca62c1d6")) ++rk;
    if (rk >= 2) hits.push_back({"SHA-1"});
}

// SHA-512 — first round constant low word: 0xd728ae22, high word: 0x428a2f98
// (same high word as SHA-256 but appears with its 64-bit pair)
static void detect_sha512(const std::string& code, std::vector<AlgoHit>& hits) {
    // 64-bit constant may be split into two 32-bit literals
    if (has(code, "0xd728ae22") && has(code, "0x428a2f98")) {
        hits.push_back({"SHA-512"});
        return;
    }
    // Library calls
    if (ihas(code, "SHA512") || ihas(code, "sha512")) {
        hits.push_back({"SHA-512 (library call)"});
    }
}

// SHA-3 (Keccak) — Iota round constants. First: 0x0000000000000001.
// Also unique theta/chi structure constants.
static void detect_sha3(const std::string& code, std::vector<AlgoHit>& hits) {
    if (ihas(code, "keccak") || ihas(code, "sha3")) {
        hits.push_back({"SHA-3/Keccak (library call)"});
        return;
    }
    // Iota round constant index 1 = 0x0000000000008082
    if (has(code, "0x8082") && has(code, "0x808a")) {
        hits.push_back({"SHA-3/Keccak"});
    }
}

// Generic SHA detection via library call names.
static void detect_sha_named(const std::string& code, std::vector<AlgoHit>& hits) {
    if (ihas(code, "SHA_Init")    || ihas(code, "SHA1_Init")   ||
        ihas(code, "SHA256_Init") || ihas(code, "SHA384_Init") ||
        ihas(code, "EVP_sha")     ||
        ihas(code, "mbedtls_sha") ||
        ihas(code, "SHA_Final")   || ihas(code, "SHA256_Final")) {
        hits.push_back({"SHA (library call)"});
    }
}

// SHA verification — SHA digest followed by a comparison against an expected
// value.  Ghidra pseudocode typically shows the result of SHA256/SHA1 passed
// directly into memcmp or compared with == 0 / != 0.
static void detect_sha_verification(const std::string& code, std::vector<AlgoHit>& hits) {
    // Must have some SHA signal.
    bool has_sha =
        has(code, "0x428a2f98") || ihas(code, "0x428a2f98") ||   // SHA-256 K[0]
        has(code, "0x71374491") || ihas(code, "0x71374491") ||   // SHA-256 K[1]
        has(code, "0x67452301") || ihas(code, "0x67452301") ||   // SHA-1 H0
        has(code, "0x5a827999") || ihas(code, "0x5a827999") ||   // SHA-1 K1
        ihas(code, "SHA256_Final") || ihas(code, "SHA1_Final")   ||
        ihas(code, "sha256_final") || ihas(code, "sha1_final")   ||
        ihas(code, "SHA256_Update") || ihas(code, "SHA1_Update") ||
        ihas(code, "EVP_sha256")   || ihas(code, "EVP_sha1");
    if (!has_sha) return;

    bool has_cmp =
        ihas(code, "memcmp") || ihas(code, "bcmp") ||
        ihas(code, "strcmp")  ||
        has(code, "== 0")    || has(code, "!= 0");
    if (has_cmp) {
        hits.push_back({"SHA integrity verification (hash+compare)"});
    }
}

// ---------------------------------------------------------------------------
// MD5 detection
// ---------------------------------------------------------------------------

// MD5 T-table constants — T[1]=0xd76aa478, T[2]=0xe8c7b756, T[3]=0x242070db.
// All three together are unique to MD5.
static void detect_md5(const std::string& code, std::vector<AlgoHit>& hits) {
    int md5c = 0;
    if (has(code, "0xd76aa478") || ihas(code, "0xd76aa478")) ++md5c;
    if (has(code, "0xe8c7b756") || ihas(code, "0xe8c7b756")) ++md5c;
    if (has(code, "0x242070db") || ihas(code, "0x242070db")) ++md5c;
    if (md5c >= 2) { hits.push_back({"MD5"}); return; }
    if (ihas(code, "MD5_Init")   || ihas(code, "MD5_Update") ||
        ihas(code, "MD5_Final")  || ihas(code, "EVP_md5")    ||
        ihas(code, "mbedtls_md5")) {
        hits.push_back({"MD5 (library call)"});
    }
}

// MD5 integrity verification — MD5 digest followed by a comparison.
// Identical structure to SHA verification but keyed on MD5 constants/calls.
static void detect_md5_verification(const std::string& code, std::vector<AlgoHit>& hits) {
    bool has_md5 =
        has(code, "0xd76aa478") || ihas(code, "0xd76aa478") ||
        has(code, "0xe8c7b756") || ihas(code, "0xe8c7b756") ||
        has(code, "0x242070db") || ihas(code, "0x242070db") ||
        ihas(code, "MD5_Final")  || ihas(code, "md5_final")  ||
        ihas(code, "MD5_Update") || ihas(code, "EVP_md5");
    if (!has_md5) return;

    bool has_cmp =
        ihas(code, "memcmp") || ihas(code, "bcmp") ||
        ihas(code, "strcmp")  ||
        has(code, "== 0")    || has(code, "!= 0");
    if (has_cmp) {
        hits.push_back({"MD5 integrity verification (hash+compare)"});
    }
}

// ---------------------------------------------------------------------------
// RC4 detection
// ---------------------------------------------------------------------------

// RC4 KSA uses a 256-byte state array, index arithmetic modulo 256, and a
// swap.  Signal: 0x100 (size) + swap pattern + modulo with same size.
static void detect_rc4(const std::string& code, std::vector<AlgoHit>& hits) {
    if (ihas(code, "rc4") || ihas(code, "arcfour")) {
        hits.push_back({"RC4 (library call)"});
        return;
    }
    bool has256 = has(code, "0x100") || has(code, "256");
    if (!has256) return;
    // Swap idiom: temp = arr[i]; arr[i] = arr[j]; arr[j] = temp
    bool has_swap = (count_occurrences(code, "= *(") >= 3 ||
                     count_occurrences(code, "swap") >= 1);
    bool has_mod  = has(code, "% 0x100") || has(code, "% 256") ||
                    has(code, "& 0xff")   || has(code, "& 0xFF");
    if (has256 && has_swap && has_mod) {
        hits.push_back({"RC4"});
    }
}

// ---------------------------------------------------------------------------
// ChaCha20 / Salsa20 detection
// ---------------------------------------------------------------------------

// ChaCha20 uses four 32-bit magic constants derived from "expand 32-byte k":
// 0x61707865 ("expa"), 0x3320646e ("nd 3"), 0x79622d32 ("2-by"), 0x6b206574 ("te k")
// Any two of these four is essentially unique to ChaCha20/Salsa20.
// Name-based matching excludes the function's own name to prevent false positives
// (e.g. chacha20_get_constant triggering "ChaCha20 (library call)").
static void detect_chacha20(const std::string& code, std::vector<AlgoHit>& hits) {
    // Name-based detection: only match if the name appears as a CALL target
    // (followed by '(') or in the body (after the first '{'), not in the
    // function's own prototype line.
    bool name_in_call = ihas(code, "chacha(") || ihas(code, "salsa20(") ||
                        ihas(code, "chacha20(") || ihas(code, "salsa(");
    bool name_in_body = false;
    {
        size_t brace = code.find('{');
        if (brace != std::string::npos) {
            std::string body(code, brace + 1);
            name_in_body = ihas(body, "chacha(") || ihas(body, "salsa20(") ||
                           ihas(body, "chacha20(") || ihas(body, "salsa(");
        }
    }
    if (name_in_call || name_in_body) {
        hits.push_back({"ChaCha20/Salsa20 (library call)"});
        return;
    }
    int cc = 0;
    if (has(code, "0x61707865")) ++cc;
    if (has(code, "0x3320646e")) ++cc;
    if (has(code, "0x79622d32")) ++cc;
    if (has(code, "0x6b206574")) ++cc;
    if (cc >= 2) hits.push_back({"ChaCha20/Salsa20"});
}

// ---------------------------------------------------------------------------
// TEA / XTEA / XXTEA detection
// ---------------------------------------------------------------------------

// TEA delta constant: 0x9e3779b9 (derived from golden ratio).
// Also used in Blowfish, but in a different context.
// Ghidra emits the negated form -0x61c88647 for subtraction patterns.
// XTEA also uses 0xC6EF3720 (delta * 32) — detectable independently.
static void detect_tea(const std::string& code, std::vector<AlgoHit>& hits) {
    // Check for TEA delta in positive or negated form
    bool has_delta = has(code, "0x9e3779b9") || ihas(code, "0x9e3779b9") ||
                     has(code, "-0x61c88647") || has(code, "+ -0x61c88647") ||
                     has(code, "+ -0x61C88647");
    // Check for XTEA sum init (0xC6EF3720) — detectable independently
    bool has_xtea_sum = has(code, "0xc6ef3720") || ihas(code, "0xc6ef3720");

    if (has_xtea_sum) {
        hits.push_back({"XTEA"});
    } else if (has_delta) {
        hits.push_back({"TEA/XTEA/XXTEA"});
    }
}

// ---------------------------------------------------------------------------
// Blowfish detection
// ---------------------------------------------------------------------------

// Blowfish P-array initialised with pi digits: P[0]=0x243F6A88, P[1]=0x85A308D3.
// Name-based matching excludes the function's own name to prevent false positives
// (e.g. blowfish_get_p triggering "Blowfish (library call)").
static void detect_blowfish(const std::string& code, std::vector<AlgoHit>& hits) {
    // Name-based detection: only match if the name appears as a CALL target
    // (followed by '(') or in the body (after the first '{'), not in the
    // function's own prototype line.
    bool name_in_call = ihas(code, "blowfish(") || ihas(code, "BF_encrypt(") ||
                        ihas(code, "BF_set_key(");
    bool name_in_body = false;
    {
        size_t brace = code.find('{');
        if (brace != std::string::npos) {
            std::string body(code, brace + 1);
            name_in_body = ihas(body, "blowfish(") || ihas(body, "BF_encrypt(") ||
                           ihas(body, "BF_set_key(");
        }
    }
    if (name_in_call || name_in_body) {
        hits.push_back({"Blowfish (library call)"});
        return;
    }
    if ((has(code, "0x243f6a88") || ihas(code, "0x243f6a88")) &&
        (has(code, "0x85a308d3") || ihas(code, "0x85a308d3"))) {
        hits.push_back({"Blowfish"});
    }
}

// ---------------------------------------------------------------------------
// DES / 3DES detection
// ---------------------------------------------------------------------------

static void detect_des(const std::string& code, std::vector<AlgoHit>& hits) {
    if (ihas(code, "DES_ecb_encrypt") || ihas(code, "DES_cbc_encrypt") ||
        ihas(code, "DES_set_key")     || ihas(code, "des_encrypt")     ||
        ihas(code, "3DES")            || ihas(code, "triple_des")      ||
        ihas(code, "mbedtls_des")) {
        hits.push_back({"DES/3DES (library call)"});
    }
}

// ---------------------------------------------------------------------------
// CRC detection
// ---------------------------------------------------------------------------

// CRC-32 Ethernet polynomial, reflected: 0xEDB88320
// Normal form: 0x04C11DB7
static void detect_crc(const std::string& code, std::vector<AlgoHit>& hits) {
    if (has(code, "0xedb88320") || ihas(code, "0xedb88320")) {
        hits.push_back({"CRC-32 (reflected polynomial)"});
        return;
    }
    if (has(code, "0x04c11db7") || ihas(code, "0x04c11db7")) {
        hits.push_back({"CRC-32"});
        return;
    }
    // CRC-16 polynomials
    if (has(code, "0x8005") || has(code, "0x1021")) {
        if (has(code, "crc") || ihas(code, "crc16") || ihas(code, "crc_16")) {
            hits.push_back({"CRC-16"});
        }
    }
}

// ---------------------------------------------------------------------------
// RSA / asymmetric detection
// ---------------------------------------------------------------------------

static void detect_rsa(const std::string& code, std::vector<AlgoHit>& hits) {
    if (ihas(code, "RSA_private_encrypt") || ihas(code, "RSA_public_encrypt") ||
        ihas(code, "RSA_private_decrypt") || ihas(code, "RSA_public_decrypt") ||
        ihas(code, "RSA_sign")            || ihas(code, "RSA_verify")         ||
        ihas(code, "BN_mod_exp")          || ihas(code, "rsa_pkcs1")          ||
        ihas(code, "mbedtls_rsa_")        || ihas(code, "EVP_PKEY_RSA")) {
        hits.push_back({"RSA (library call)"});
    }
}

// ---------------------------------------------------------------------------
// Elliptic curve detection
// ---------------------------------------------------------------------------

static void detect_ecc(const std::string& code, std::vector<AlgoHit>& hits) {
    if (ihas(code, "EC_KEY_new")      || ihas(code, "EC_POINT_add")  ||
        ihas(code, "ECDSA_sign")      || ihas(code, "ECDSA_verify")  ||
        ihas(code, "curve25519")      || ihas(code, "X25519")        ||
        ihas(code, "ed25519")         || ihas(code, "mbedtls_ecdsa") ||
        ihas(code, "mbedtls_ecdh")    || ihas(code, "EVP_PKEY_EC")) {
        hits.push_back({"Elliptic curve crypto (library call)"});
    }
}

// ---------------------------------------------------------------------------
// HMAC detection
// ---------------------------------------------------------------------------

static void detect_hmac(const std::string& code, std::vector<AlgoHit>& hits) {
    if (ihas(code, "HMAC_Init")   || ihas(code, "HMAC_Update") ||
        ihas(code, "HMAC_Final")  || ihas(code, "HMAC_CTX")    ||
        ihas(code, "mbedtls_md_hmac") ||
        (ihas(code, "hmac") && (ihas(code, "sha") || ihas(code, "md5")))) {
        hits.push_back({"HMAC"});
    }
}

// ---------------------------------------------------------------------------
// Key derivation detection
// ---------------------------------------------------------------------------

static void detect_kdf(const std::string& code, std::vector<AlgoHit>& hits) {
    if (ihas(code, "PKCS5_PBKDF2") || ihas(code, "pbkdf2")     ||
        ihas(code, "EVP_BytesToKey") || ihas(code, "scrypt")    ||
        ihas(code, "bcrypt")         || ihas(code, "argon2")    ||
        ihas(code, "mbedtls_pkcs5_pbkdf2")) {
        hits.push_back({"Key derivation (PBKDF/scrypt/bcrypt)"});
    }
}

// ---------------------------------------------------------------------------
// Base64 detection
// ---------------------------------------------------------------------------

// The base64 alphabet is unique: 64 printable chars in a 64 or 65-byte table.
// Also detectable by the shift/mask operations (6-bit groupings).
// Ghidra emits shift amounts as hex (>> 0x12, >> 0xc) — detect any right
// shift combined with the 0x3F mask, which is the base64 signature.
static void detect_base64(const std::string& code, std::vector<AlgoHit>& hits) {
    // The standard alphabet as a string literal
    if (has(code, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")) {
        hits.push_back({"Base64 encode/decode"});
        return;
    }
    // URL-safe variant
    if (has(code, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")) {
        hits.push_back({"Base64url encode/decode"});
        return;
    }
    // 6-bit grouping: right shift (>> 6, >> 0xc, >> 0x12, etc.) + 0x3F mask
    bool has_right_shift = has(code, ">> 6") || has(code, ">>6") ||
                           has(code, ">> 0x6") || has(code, ">>0x6") ||
                           has(code, ">> 0xc") || has(code, ">> 0x12");
    bool has_mask = has(code, "& 0x3f") || has(code, "& 0x3F") ||
                    has(code, "& 63") || has(code, "&0x3f") ||
                    has(code, "&0x3F");
    if (has_right_shift && has_mask) {
        hits.push_back({"Base64 encode/decode"});
    }
}

// ---------------------------------------------------------------------------
// Diffie-Hellman detection
// ---------------------------------------------------------------------------

static void detect_dh(const std::string& code, std::vector<AlgoHit>& hits) {
    if (ihas(code, "DH_new")       || ihas(code, "DH_compute_key") ||
        ihas(code, "DH_generate")  || ihas(code, "mbedtls_dhm")    ||
        ihas(code, "EVP_PKEY_DH")) {
        hits.push_back({"Diffie-Hellman key exchange (library call)"});
    }
}

// ---------------------------------------------------------------------------
// Generic TLS / SSL detection
// ---------------------------------------------------------------------------

static void detect_tls(const std::string& code, std::vector<AlgoHit>& hits) {
    if (ihas(code, "SSL_CTX_new")  || ihas(code, "SSL_connect")    ||
        ihas(code, "SSL_accept")   || ihas(code, "SSL_read")        ||
        ihas(code, "SSL_write")    || ihas(code, "mbedtls_ssl_")    ||
        ihas(code, "TLS_method")   || ihas(code, "TLS_client_method")) {
        hits.push_back({"TLS/SSL"});
    }
}

// ---------------------------------------------------------------------------
// Poly1305 / GHASH (authentication tags) detection
// ---------------------------------------------------------------------------

static void detect_poly1305(const std::string& code, std::vector<AlgoHit>& hits) {
    if (ihas(code, "poly1305") || ihas(code, "ghash") ||
        ihas(code, "GHASH")    || ihas(code, "Poly1305")) {
        hits.push_back({"Poly1305/GHASH MAC"});
    }
    // ChaCha20-Poly1305 AEAD
    if (ihas(code, "chacha20_poly1305") || ihas(code, "CHACHA20_POLY1305")) {
        hits.push_back({"ChaCha20-Poly1305 AEAD"});
    }
}

// ---------------------------------------------------------------------------
// Whirlpool detection
// ---------------------------------------------------------------------------

static void detect_whirlpool(const std::string& code, std::vector<AlgoHit>& hits) {
    // Whirlpool uses a specific mini-box constant: 0x18186018c07830d8
    if (has(code, "0x18186018") && has(code, "0xc07830d8")) {
        hits.push_back({"Whirlpool hash"});
    }
}

// ---------------------------------------------------------------------------
// RIPEMD detection
// ---------------------------------------------------------------------------

static void detect_ripemd(const std::string& code, std::vector<AlgoHit>& hits) {
    if (ihas(code, "RIPEMD") || ihas(code, "ripemd") ||
        ihas(code, "RMD160") || ihas(code, "rmd160")) {
        hits.push_back({"RIPEMD (library call)"});
    }
}

// ---------------------------------------------------------------------------
// Common key material / key format detection
// ---------------------------------------------------------------------------

// Detects encoded or hardcoded key material in several common forms:
//   - PEM armour headers (BEGIN PRIVATE KEY, BEGIN CERTIFICATE, …)
//   - PKCS#1/8/12 string tokens
//   - JWT / JWK patterns
//   - Android Keystore API calls (key not stored in code but generated)
//   - Hardcoded hex key string: 32+ consecutive hex chars in a string literal
//     (= 128-bit key minimum; 64 hex chars = 256-bit AES key)
//   - Hardcoded byte-array key: 16+ consecutive 0xNN, 0xNN, … literals
//     on one logical line (typical of embedded AES/ChaCha key arrays)
static void detect_key_material(const std::string& code, std::vector<AlgoHit>& hits) {
    // PEM armour
    if (has(code, "-----BEGIN") || has(code, "BEGIN PRIVATE KEY") ||
        has(code, "BEGIN RSA PRIVATE KEY")  || has(code, "BEGIN EC PRIVATE KEY")  ||
        has(code, "BEGIN PUBLIC KEY")       || has(code, "BEGIN CERTIFICATE")     ||
        has(code, "BEGIN ENCRYPTED PRIVATE KEY")) {
        hits.push_back({"PEM-encoded key / certificate"});
    }

    // PKCS tokens
    if (ihas(code, "PKCS12") || ihas(code, "PKCS8") || ihas(code, "PKCS1") ||
        ihas(code, "pkcs12") || ihas(code, "pkcs8") || ihas(code, "pkcs1")) {
        hits.push_back({"PKCS key format"});
    }

    // JWT / JWK
    // "eyJ" is the base64url encoding of '{"' — every JWT header starts with it.
    if (has(code, "eyJ") ||
        (ihas(code, "jwt")  && (ihas(code, "token") || ihas(code, "sign"))) ||
        (ihas(code, "jwk")  && (ihas(code, "key")   || ihas(code, "set")))  ||
        ihas(code, "alg\":\"RS") || ihas(code, "alg\":\"HS") ||
        ihas(code, "alg\":\"ES")) {
        hits.push_back({"JWT / JWK token handling"});
    }

    // Hardcoded hex key string — 32+ consecutive hex digits inside quotes.
    // 32 hex = 128-bit (AES-128 key); 48 = 192-bit; 64 = 256-bit.
    {
        size_t pos = 0;
        while ((pos = code.find('"', pos)) != std::string::npos) {
            ++pos;
            size_t start = pos;
            while (pos < code.size() && std::isxdigit((unsigned char)code[pos])) ++pos;
            size_t len = pos - start;
            if (len >= 32 && pos < code.size() && code[pos] == '"') {
                hits.push_back({"Hardcoded hex key string (" +
                                std::to_string(len * 4) + "-bit)"});
                break;
            }
        }
    }

    // Hardcoded byte-array key — 16+ "0xNN," or "0xNN }" consecutive tokens
    // on a single logical line (compiler-initialised static key array).
    // We walk line by line and count 0xNN tokens of exactly 2 hex digits.
    {
        size_t line_start = 0;
        while (line_start < code.size()) {
            size_t line_end = code.find('\n', line_start);
            if (line_end == std::string::npos) line_end = code.size();
            if (line_end > line_start) {
                const std::string line(code.c_str() + line_start, line_end - line_start);
                // Count "0x??" tokens where ?? are exactly 2 hex digits.
                int byte_count = 0;
                size_t p = 0;
                while ((p = line.find("0x", p)) != std::string::npos) {
                    p += 2;
                    size_t hstart = p;
                    while (p < line.size() &&
                           std::isxdigit((unsigned char)line[p])) ++p;
                    if (p - hstart == 2) ++byte_count;
                }
                if (byte_count >= 16) {
                    hits.push_back({"Hardcoded key byte array (" +
                                    std::to_string(byte_count * 8) + "-bit)"});
                    break;
                }
            }
            line_start = line_end + 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Detection table — comment out any row to disable that detection entirely.
// ---------------------------------------------------------------------------

using DetectorFn = void (*)(const std::string&, std::vector<AlgoHit>&);

static const DetectorFn kDetectors[] = {
    // XOR / obfuscation (ordered most-specific first)
    detect_ay_obfuscate,
    detect_rolling_xor,
    detect_single_byte_xor_key,
    detect_xor_constant,
    detect_xor_loop,
    // AES
    detect_aes_named,
    detect_aes_sbox,
    detect_aes_rcon,
    detect_aes_key,           // ARM64 HW / SubWord / key-size selection
    // SHA family
    detect_sha256,
    detect_sha1,
    detect_sha512,
    detect_sha3,
    detect_sha_named,
    detect_sha_verification,  // SHA + memcmp integrity check
    // MD5
    detect_md5,
    detect_md5_verification,  // MD5 + memcmp integrity check
    // Stream ciphers
    detect_rc4,
    detect_chacha20,
    detect_poly1305,
    // Block ciphers
    detect_tea,
    detect_blowfish,
    detect_des,
    // Asymmetric
    detect_rsa,
    detect_ecc,
    detect_dh,
    // MAC / hash
    detect_hmac,
    detect_kdf,
    // Integrity / encoding
    detect_crc,
    detect_base64,
    detect_whirlpool,
    detect_ripemd,
    // Transport
    detect_tls,
    // Key material / key formats
    detect_key_material,
};
static const size_t kDetectorCount = sizeof(kDetectors) / sizeof(kDetectors[0]);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

std::vector<AlgoHit> detect_algorithms(const std::string& pseudocode) {
    std::vector<AlgoHit> hits;
    for (size_t i = 0; i < kDetectorCount; ++i)
        kDetectors[i](pseudocode, hits);

    // Deduplicate by name while preserving first-occurrence order.
    std::set<std::string> seen;
    std::vector<AlgoHit> unique;
    for (auto& h : hits) {
        if (seen.insert(h.name).second)
            unique.push_back(std::move(h));
    }
    return unique;
}

std::string annotate_algorithms(const std::string& pseudocode) {
    std::vector<AlgoHit> hits = detect_algorithms(pseudocode);
    if (hits.empty()) return pseudocode;

    std::string prefix;
    for (const auto& h : hits) {
        prefix += "// detected - ";
        prefix += h.name;
        prefix += " (detection may be wrong)\n";
    }
    return prefix + pseudocode;
}
