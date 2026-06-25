package com.nex.peek

import android.app.Application
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter

/**
 * Last-resort crash capture. This exists because native crashes (a real
 * SIGSEGV/SIGABRT inside the C++ decompiler code) kill the process silently
 * — there's no Java exception to catch, and the app has no chance to show
 * its own UI once the process is already dying. So instead of trying to
 * show anything *during* the crash, we write the reason to a small file
 * BEFORE the process dies, and show it as a Toast the NEXT time the app
 * launches.
 *
 * Two layers:
 *  1. Thread.setDefaultUncaughtExceptionHandler — catches Java/Kotlin-level
 *     crashes (NullPointerException, OutOfMemoryError, etc).
 *  2. A native signal handler (installed via JNI, see crash_handler.cpp) —
 *     catches actual native crashes (SIGSEGV, SIGABRT) that no Java handler
 *     can ever see, since these happen below the JVM entirely.
 */
class PeekApplication : Application() {

    companion object {
        const val CRASH_FILE_NAME = "last_crash.txt"
    }

    override fun onCreate() {
        super.onCreate()

        val crashFile = File(filesDir, CRASH_FILE_NAME)

        // Layer 1: Java/Kotlin uncaught exceptions.
        val previousHandler = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            try {
                val sw = StringWriter()
                throwable.printStackTrace(PrintWriter(sw))
                crashFile.writeText(
                    "Java crash on thread '${thread.name}':\n${sw}"
                )
            } catch (_: Exception) {
                // If we can't even write the crash file, there's nothing
                // more we can safely do here — fall through to the
                // previous handler below.
            }
            previousHandler?.uncaughtException(thread, throwable)
        }

        // Layer 2: native signal handler. installNativeCrashHandler writes
        // directly to crashFile's path from C++ signal-handler context if
        // a SIGSEGV/SIGABRT/etc occurs — see crash_handler.cpp for why this
        // has to be done with only signal-safe calls (no JNI, no malloc).
        PeekNative.installNativeCrashHandler(crashFile.absolutePath)
    }
}
