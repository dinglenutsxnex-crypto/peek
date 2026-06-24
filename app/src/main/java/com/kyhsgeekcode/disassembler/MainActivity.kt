package com.kyhsgeekcode.disassembler

//import com.gu.toolargetool.TooLargeTool

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Process
import android.util.Log
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.ExperimentalFoundationApi
import com.kyhsgeekcode.disassembler.PermissionUtils.requestAppPermissions
import com.kyhsgeekcode.disassembler.disasmtheme.ColorHelper
import com.kyhsgeekcode.disassembler.ui.MainScreen
import com.kyhsgeekcode.disassembler.utils.CrashReportingTree
import com.kyhsgeekcode.disassembler.viewmodel.MainViewModel
import com.kyhsgeekcode.sendErrorReport
import kotlinx.serialization.ExperimentalSerializationApi
import timber.log.Timber
import timber.log.Timber.*
import java.util.*
import java.util.concurrent.LinkedBlockingQueue


class MainActivity : AppCompatActivity() {

    companion object {
        const val SETTINGKEY = "setting"
        const val REQUEST_WRITE_STORAGE_REQUEST_CODE = 1

        private const val RATIONALSETTING = "showRationals"

        /**
         * @returns handle : Int
         */
        @JvmStatic
        external fun Open(arch: Int, mode: Int): Int

        @JvmStatic
        external fun Finalize(handle: Int)

        init {
            System.loadLibrary("native-lib")
        }
    }

    private var toDoAfterPermQueue: Queue<Runnable> = LinkedBlockingQueue()


    private val viewModel by viewModels<MainViewModel>()

    /** A tree which logs important information for crash reporting.  */

    @OptIn(ExperimentalFoundationApi::class)
    public override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (BuildConfig.DEBUG) {
            Timber.plant(DebugTree())
        } else {
            Timber.plant(CrashReportingTree())
        }
        //        setupUncaughtException()
        initNative()
        if (shouldHandleIncomingIntent(intent, savedInstanceState)) {
            handleIncomingIntent(intent)
        }

        setContent {
            MainScreen(viewModel = viewModel)
        }
    }

    @OptIn(ExperimentalSerializationApi::class)
    override fun onResume() {
        super.onResume()
        ColorHelper.populatePalettes(context = this)
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (hasIncomingIntent(intent)) {
            handleIncomingIntent(intent)
        }
    }

    private fun handleIncomingIntent(intent: Intent?) {
        val incomingIntent = intent ?: return
        val incomingUri = extractIncomingUri(incomingIntent) ?: return
        takePersistableReadPermissionIfPossible(incomingUri, incomingIntent.flags)
        incomingIntent.putExtra("uri", incomingUri)
        viewModel.onSelectIntent(incomingIntent)
    }

    private fun takePersistableReadPermissionIfPossible(uri: Uri, intentFlags: Int) {
        val persistFlags = persistableUriPermissionFlags(uri, intentFlags)
        if (persistFlags == 0) {
            return
        }
        try {
            contentResolver.takePersistableUriPermission(uri, persistFlags)
        } catch (e: SecurityException) {
            Timber.w(e, "Persistable URI permission not available for %s", uri)
        }
    }

    private fun setupUncaughtException() {
        Thread.setDefaultUncaughtExceptionHandler { _: Thread?, p2: Throwable ->
            runOnUiThread {
                Toast.makeText(this@MainActivity, Log.getStackTraceString(p2), Toast.LENGTH_SHORT)
                    .show()
            }
            if (p2 is SecurityException) {
                Toast.makeText(this@MainActivity, R.string.didUgrant, Toast.LENGTH_SHORT).show()
                val permSetting = getSharedPreferences(RATIONALSETTING, MODE_PRIVATE)
                val permEditor = permSetting.edit()
                permEditor.putBoolean("show", true)
                permEditor.apply()
            }
            requestAppPermissions(this@MainActivity)
            // String [] accs=getAccounts();
            sendErrorReport(p2)
            // 	ori.uncaughtException(p1, p2);
            Timber.wtf(p2, "UncaughtException")
            finish()
        }
    }

    private fun initNative() {
        try {
            if (Init() == -1) {
                throw RuntimeException()
            }
        } catch (e: Exception) {
            Toast.makeText(
                this,
                "Failed to initialize the native engine: " + Log.getStackTraceString(e),
                Toast.LENGTH_LONG
            ).show()
            Process.killProcess(Process.getGidForName(null))
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        when (requestCode) {
            REQUEST_WRITE_STORAGE_REQUEST_CODE -> {
                // If request is cancelled, the result arrays are empty.
                if (grantResults.isNotEmpty() &&
                    grantResults[0] == PackageManager.PERMISSION_GRANTED
                ) { // permission was granted, yay! Do the
// contacts-related task you need to do.
                    while (!toDoAfterPermQueue.isEmpty()) {
                        val run = toDoAfterPermQueue.remove()
                        run?.run()
                    }
                } else {
                    Toast.makeText(this, R.string.permission_needed, Toast.LENGTH_LONG).show()
                    val showRationalSetting =
                        getSharedPreferences(RATIONALSETTING, Context.MODE_PRIVATE)
                    val showRationalEditor = showRationalSetting.edit()
                    showRationalEditor.putBoolean("show", true)
                    showRationalEditor.apply()
                    finish()
                    // permission denied, boo! Disable the
                    // functionality that depends on this permission.
                }
            }
        }
    }

    external fun Init(): Int
}

private fun extractIncomingUri(intent: Intent): Uri? {
    return intent.data
        ?: if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableExtra(Intent.EXTRA_STREAM)
        }
}

internal fun hasIncomingIntent(intent: Intent?): Boolean {
    if (intent == null) {
        return false
    }
    return extractIncomingUri(intent) != null
}

internal fun shouldHandleIncomingIntent(hasIncomingIntent: Boolean, hasSavedState: Boolean): Boolean {
    return !hasSavedState && hasIncomingIntent
}

internal fun shouldHandleIncomingIntent(intent: Intent?, savedInstanceState: Bundle?): Boolean {
    return shouldHandleIncomingIntent(
        hasIncomingIntent = hasIncomingIntent(intent),
        hasSavedState = savedInstanceState != null
    )
}
