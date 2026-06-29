package com.nex.peek

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import android.view.LayoutInflater
import android.view.View
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import androidx.core.view.updatePadding
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.google.android.material.card.MaterialCardView
import com.nex.peek.adapter.RecentProjectsAdapter
import com.nex.peek.databinding.ActivityMainBinding
import com.nex.peek.ui.AnalysisSession
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream

class MainActivity : AppCompatActivity() {

    private lateinit var b: ActivityMainBinding
    private lateinit var recentAdapter: RecentProjectsAdapter

    private val filePicker = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) openBinary(uri)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        WindowCompat.setDecorFitsSystemWindows(window, false)
        super.onCreate(savedInstanceState)
        b = ActivityMainBinding.inflate(layoutInflater)
        setContentView(b.root)

        showPendingCrashIfAny()

        WindowInsetsControllerCompat(window, window.decorView).apply {
            hide(WindowInsetsCompat.Type.navigationBars())
            systemBarsBehavior =
                WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            window.isNavigationBarContrastEnforced = false
            window.isStatusBarContrastEnforced = false
        }

        ViewCompat.setOnApplyWindowInsetsListener(b.root) { v, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.updatePadding(top = bars.top)
            insets
        }

        lifecycleScope.launch(Dispatchers.IO) {
            val specDir = extractDecompilerAssets()
            PeekNative.initDecompiler(specDir)
        }

        recentAdapter = RecentProjectsAdapter { info ->
            reopenCachedBinary(info)
        }
        b.rvRecent.layoutManager = LinearLayoutManager(this)
        b.rvRecent.adapter = recentAdapter

        b.btnOpen.setOnClickListener {
            showTargetTypeDialog()
        }
    }

    override fun onResume() {
        super.onResume()
        loadRecentProjects()
    }

    private fun loadRecentProjects() {
        lifecycleScope.launch {
            val list = withContext(Dispatchers.IO) {
                PeekNative.listBinaries(filesDir.absolutePath)
            }
            recentAdapter.submitList(list)
            b.tvEmpty.visibility = if (list.isEmpty()) View.VISIBLE else View.GONE
        }
    }

    private fun reopenCachedBinary(info: PeekNative.BinaryInfo) {
        val file = File(info.path)
        if (!file.exists()) {
            android.widget.Toast.makeText(this, "File not found: ${info.name}", android.widget.Toast.LENGTH_SHORT).show()
            return
        }

        b.progressBar.visibility = View.VISIBLE
        b.tvStatus.text = "Loading…"
        b.btnOpen.isEnabled = false

        lifecycleScope.launch {
            val handle = withContext(Dispatchers.IO) {
                PeekNative.openBinary(info.path, filesDir.absolutePath)
            }

            b.progressBar.visibility = View.GONE
            b.btnOpen.isEnabled = true

            if (handle == 0L) {
                b.tvStatus.text = "Failed to reload."
                return@launch
            }

            AnalysisSession.set(handle)
            startActivity(
                Intent(this@MainActivity, AnalysisActivity::class.java)
                    .putExtra(AnalysisActivity.EXTRA_NAME, info.name)
            )
            b.tvStatus.text = ""
        }
    }

    // -----------------------------------------------------------------------
    // Target type selection dialog
    // -----------------------------------------------------------------------

    private fun showTargetTypeDialog() {
        val dialogView = LayoutInflater.from(this)
            .inflate(R.layout.dialog_target_type, null)

        val dialog = AlertDialog.Builder(this)
            .setView(dialogView)
            .create()

        dialog.window?.setBackgroundDrawableResource(android.R.color.transparent)

        dialogView.findViewById<MaterialCardView>(R.id.cardUnity).setOnClickListener {
            dialog.dismiss()
            startActivity(Intent(this, UnityLoaderActivity::class.java))
        }

        dialogView.findViewById<MaterialCardView>(R.id.cardStandard).setOnClickListener {
            dialog.dismiss()
            filePicker.launch(arrayOf("application/octet-stream", "*/*"))
        }

        dialog.show()
    }

    // -----------------------------------------------------------------------
    // Standard binary loading
    // -----------------------------------------------------------------------

    private fun openBinary(uri: Uri) {
        b.progressBar.visibility = View.VISIBLE
        b.tvStatus.text = "Copying file…"
        b.btnOpen.isEnabled = false

        lifecycleScope.launch {
            val name = queryFileName(uri) ?: "binary.so"
            val path = withContext(Dispatchers.IO) { copyToStorage(uri, name) }

            if (path == null) {
                b.progressBar.visibility = View.GONE
                b.tvStatus.text = "Failed to read file."
                b.btnOpen.isEnabled = true
                return@launch
            }

            b.tvStatus.text = "Analysing…"
            val handle = withContext(Dispatchers.IO) {
                PeekNative.openBinary(path, filesDir.absolutePath)
            }

            b.progressBar.visibility = View.GONE
            b.btnOpen.isEnabled = true

            if (handle == 0L) {
                b.tvStatus.text = "Analysis failed."
                return@launch
            }

            AnalysisSession.set(handle)
            startActivity(
                Intent(this@MainActivity, AnalysisActivity::class.java)
                    .putExtra(AnalysisActivity.EXTRA_NAME, name)
            )
            b.tvStatus.text = ""
        }
    }

    /**
     * Copies the picked file to filesDir/binaries/ so it persists across
     * Android low-storage cacheDir purges.
     */
    private fun copyToStorage(uri: Uri, name: String): String? {
        return try {
            val dir = File(filesDir, "binaries").also { it.mkdirs() }
            val dest = File(dir, name)
            contentResolver.openInputStream(uri)?.use { input ->
                FileOutputStream(dest).use { output -> input.copyTo(output) }
            }
            dest.absolutePath
        } catch (_: Exception) { null }
    }

    /**
     * Extracts decompiler SLEIGH spec assets to filesDir/decompiler_spec/ on
     * first run (skips files that already exist).  Returns the directory path.
     */
    private fun extractDecompilerAssets(): String {
        val dir = File(filesDir, "decompiler_spec")
        dir.mkdirs()
        val files = listOf("AARCH64.sla", "AARCH64.ldefs", "AARCH64.pspec", "AARCH64.cspec")
        for (name in files) {
            val dest = File(dir, name)
            if (!dest.exists()) {
                try {
                    assets.open(name).use { input ->
                        FileOutputStream(dest).use { out -> input.copyTo(out) }
                    }
                } catch (_: Exception) {}
            }
        }
        return dir.absolutePath
    }

    private fun queryFileName(uri: Uri): String? {
        return contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val col = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (cursor.moveToFirst() && col >= 0) cursor.getString(col) else null
        }
    }

    /**
     * If the app died last run (either a Java exception caught by
     * PeekApplication's uncaught-exception handler, or a real native
     * SIGSEGV/SIGABRT caught by the signal handler in crash_handler.cpp),
     * a reason was written to this file just before death. Show it now —
     * a Toast first (so it's visible without any interaction), then a dialog
     * since native crash messages can be longer than a Toast comfortably displays.
     * Then delete the file so it isn't shown again.
     */
    private fun showPendingCrashIfAny() {
        val crashFile = File(filesDir, PeekApplication.CRASH_FILE_NAME)
        if (!crashFile.exists()) return

        var reason = try {
            crashFile.readText().trim()
        } catch (e: Exception) {
            "Could not read crash file: ${e.message}"
        }
        crashFile.delete()

        val funcFile = File(filesDir, PeekApplication.DOWNLOAD_FUNC_FILE)
        if (funcFile.exists()) {
            val funcName = try { funcFile.readText().trim() } catch (_: Exception) { "" }
            funcFile.delete()
            if (funcName.isNotEmpty()) {
                reason += "\n\nOccurred while downloading function:\n$funcName"
            }
        }

        if (reason.isEmpty()) return

        android.widget.Toast.makeText(
            this,
            "App crashed last run — tap here for details",
            android.widget.Toast.LENGTH_LONG
        ).show()

        AlertDialog.Builder(this)
            .setTitle("Last run crashed")
            .setMessage(reason)
            .setPositiveButton("OK", null)
            .show()
    }
}
