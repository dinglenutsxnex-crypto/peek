package com.nex.peek

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.view.MenuItem
import android.view.View
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import androidx.lifecycle.lifecycleScope
import com.nex.peek.databinding.ActivityUnityLoaderBinding
import com.nex.peek.ui.AnalysisSession
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream

class UnityLoaderActivity : AppCompatActivity() {

    private lateinit var b: ActivityUnityLoaderBinding

    private var soPath:   String? = null
    private var metaPath: String? = null
    private var analysisRunning = false

    private val soPicker = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) handleSoPicked(uri)
    }

    private val metaPicker = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) handleMetaPicked(uri)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        WindowCompat.setDecorFitsSystemWindows(window, false)
        super.onCreate(savedInstanceState)
        b = ActivityUnityLoaderBinding.inflate(layoutInflater)
        setContentView(b.root)

        setSupportActionBar(b.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)

        ViewCompat.setOnApplyWindowInsetsListener(b.root) { v, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.updatePadding(top = bars.top)
            insets
        }

        b.cardSo.setOnClickListener {
            if (!analysisRunning)
                soPicker.launch(arrayOf("application/octet-stream", "*/*"))
        }

        b.cardMeta.setOnClickListener {
            if (!analysisRunning)
                metaPicker.launch(arrayOf("application/octet-stream", "*/*"))
        }
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) { finish(); return true }
        return super.onOptionsItemSelected(item)
    }

    private fun handleSoPicked(uri: Uri) {
        val name = queryFileName(uri) ?: "il2cpp.so"
        appendLog("> Loading il2cpp.so: $name")
        b.tvSoStatus.text = "Copying…"

        lifecycleScope.launch {
            val path = withContext(Dispatchers.IO) { copyToCache(uri, name) }
            if (path == null) {
                b.tvSoStatus.text = "Failed to read file"
                appendLog("ERROR: Failed to copy il2cpp.so")
            } else {
                soPath = path
                b.tvSoStatus.text = name
                appendLog("> il2cpp.so ready")
                maybeStartAnalysis()
            }
        }
    }

    private fun handleMetaPicked(uri: Uri) {
        val name = queryFileName(uri) ?: "global-metadata.dat"
        appendLog("> Loading metadata: $name")
        b.tvMetaStatus.text = "Copying…"

        lifecycleScope.launch {
            val path = withContext(Dispatchers.IO) { copyToCache(uri, name) }
            if (path == null) {
                b.tvMetaStatus.text = "Failed to read file"
                appendLog("ERROR: Failed to copy global-metadata.dat")
            } else {
                metaPath = path
                b.tvMetaStatus.text = name
                appendLog("> global-metadata.dat ready")
                maybeStartAnalysis()
            }
        }
    }

    private fun maybeStartAnalysis() {
        val so   = soPath   ?: return
        val meta = metaPath ?: return
        if (analysisRunning) return
        analysisRunning = true

        appendLog("\n> Both files ready. Starting IL2CPP analysis…")

        lifecycleScope.launch {
            val handle = withContext(Dispatchers.IO) {
                PeekNative.openUnityBinary(so, meta, filesDir.absolutePath)
            }

            val dumpLog = withContext(Dispatchers.IO) {
                PeekNative.getIl2CppLog(handle)
            }

            if (dumpLog.isNotEmpty()) {
                for (line in dumpLog.trim().lines()) {
                    appendLog("> $line")
                }
            }

            analysisRunning = false

            if (handle == 0L) {
                appendLog("\nERROR: Analysis failed.")
                return@launch
            }

            appendLog("\n> Done. Opening binary view…")

            val soName = File(so).name
            AnalysisSession.set(handle)
            startActivity(
                Intent(this@UnityLoaderActivity, AnalysisActivity::class.java)
                    .putExtra(AnalysisActivity.EXTRA_NAME, soName)
                    .putExtra(AnalysisActivity.EXTRA_IS_UNITY, true)
            )
        }
    }

    private fun appendLog(line: String) {
        runOnUiThread {
            val current = b.tvLog.text.toString()
            val newText = if (current == "> Waiting for target files...") line
                          else "$current\n$line"
            b.tvLog.text = newText
            b.scrollLog.post { b.scrollLog.fullScroll(View.FOCUS_DOWN) }
        }
    }

    private fun copyToCache(uri: Uri, name: String): String? {
        return try {
            val dest = File(cacheDir, "unity_$name")
            contentResolver.openInputStream(uri)?.use { input ->
                FileOutputStream(dest).use { out -> input.copyTo(out) }
            }
            dest.absolutePath
        } catch (_: Exception) { null }
    }

    private fun queryFileName(uri: Uri): String? {
        return contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val col = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (cursor.moveToFirst() && col >= 0) cursor.getString(col) else null
        }
    }
}
