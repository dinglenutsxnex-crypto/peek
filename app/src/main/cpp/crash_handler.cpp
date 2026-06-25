// crash_handler.cpp
//
// Installs a native signal handler so that a real crash (SIGSEGV from a bad
// pointer deref, SIGABRT from an assert/abort, etc — the kind of crash that
// kills the process with zero Java-visible exception) leaves behind a
// human-readable reason on disk, instead of vanishing silently.
//
// IMPORTANT: signal handlers run in a very restricted context. The process
// may already have corrupted memory, a corrupted heap, or be on a thread
// with no Java/JNI environment attached. We must ONLY use functions that
// are documented as "async-signal-safe" — no malloc/new, no C++ exceptions,
// no JNI calls, no iostream. We use raw POSIX write()/open() and a fixed
// stack buffer instead.

#include <android/log.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#define LOG_TAG "PeekCrash"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace {

// Fixed-size buffer for the crash file path — set once at install time,
// before any crash can occur, so the handler itself never needs to
// allocate anything.
char g_crash_path[1024] = {0};

const char* signal_name(int sig) {
    switch (sig) {
        case SIGSEGV: return "SIGSEGV (invalid memory access)";
        case SIGABRT: return "SIGABRT (abort/assert)";
        case SIGBUS:  return "SIGBUS (bad memory alignment/access)";
        case SIGILL:  return "SIGILL (illegal instruction)";
        case SIGFPE:  return "SIGFPE (arithmetic error, e.g. divide by zero)";
        default:      return "unknown signal";
    }
}

// Async-signal-safe: converts an unsigned integer to decimal text into buf,
// returns the number of characters written. No snprintf/sprintf, since
// their signal-safety is not guaranteed on all libc implementations.
int write_uint(char* buf, unsigned long val) {
    char tmp[24];
    int n = 0;
    if (val == 0) {
        buf[0] = '0';
        return 1;
    }
    while (val > 0) {
        tmp[n++] = (char)('0' + (val % 10));
        val /= 10;
    }
    for (int i = 0; i < n; i++) {
        buf[i] = tmp[n - 1 - i];
    }
    return n;
}

void crash_handler(int sig, siginfo_t* info, void* /*ucontext*/) {
    // Build the message using only stack memory and raw syscalls.
    char msg[512];
    int pos = 0;

    const char* prefix = "Native crash: ";
    size_t plen = strlen(prefix);
    memcpy(msg + pos, prefix, plen);
    pos += (int)plen;

    const char* name = signal_name(sig);
    size_t nlen = strlen(name);
    memcpy(msg + pos, name, nlen);
    pos += (int)nlen;

    const char* addr_label = " at fault address 0x";
    size_t alen = strlen(addr_label);
    memcpy(msg + pos, addr_label, alen);
    pos += (int)alen;

    // info->si_addr is the faulting address for SIGSEGV/SIGBUS — extremely
    // useful for correlating against a known bad address (e.g. an
    // out-of-range Address we constructed) even without a full backtrace.
    unsigned long fault_addr = (unsigned long)info->si_addr;
    char hexbuf[20];
    int hexlen = 0;
    if (fault_addr == 0) {
        hexbuf[0] = '0';
        hexlen = 1;
    } else {
        const char* digits = "0123456789abcdef";
        char tmp[16];
        int n = 0;
        unsigned long v = fault_addr;
        while (v > 0) {
            tmp[n++] = digits[v & 0xF];
            v >>= 4;
        }
        for (int i = 0; i < n; i++) hexbuf[hexlen++] = tmp[n - 1 - i];
    }
    memcpy(msg + pos, hexbuf, hexlen);
    pos += hexlen;

    msg[pos++] = '\n';

    // Also log it the normal way in case logcat IS available/captured —
    // this costs nothing extra and helps if a debugger happens to be
    // attached when it happens.
    LOGE("%.*s", pos, msg);

    if (g_crash_path[0] != '\0') {
        int fd = open(g_crash_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            write(fd, msg, (size_t)pos);
            close(fd);
        }
    }

    // Re-raise with the default handler so the OS still produces its own
    // normal crash handling (tombstone, process death) afterward — we are
    // only adding our own diagnostic write, not replacing Android's own
    // crash machinery.
    signal(sig, SIG_DFL);
    raise(sig);
}

} // namespace

extern "C" void peek_install_native_crash_handler(const char* crash_file_path) {
    size_t len = strlen(crash_file_path);
    if (len >= sizeof(g_crash_path)) {
        len = sizeof(g_crash_path) - 1;
    }
    memcpy(g_crash_path, crash_file_path, len);
    g_crash_path[len] = '\0';

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO;

    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGABRT, &sa, nullptr);
    sigaction(SIGBUS, &sa, nullptr);
    sigaction(SIGILL, &sa, nullptr);
    sigaction(SIGFPE, &sa, nullptr);

    LOGE("Native crash handler installed, writing to: %s", g_crash_path);
}
