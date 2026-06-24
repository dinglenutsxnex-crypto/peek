package com.nex.peek

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import android.view.View
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import androidx.core.view.updatePadding
import androidx.lifecycle.lifecycleScope
import com.nex.peek.databinding.ActivityMainBinding
import com.nex.peek.ui.AnalysisSession
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream

class MainActivity : AppCompatActivity() {

    private lateinit var b: ActivityMainBinding

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

        b.btnOpen.setOnClickListener {
            filePicker.launch(arrayOf("application/octet-stream", "*/*"))
        }
    }

    private fun openBinary(uri: Uri) {
        b.progressBar.visibility = View.VISIBLE
        b.tvStatus.text = "Copying file…"
        b.btnOpen.isEnabled = false

        lifecycleScope.launch {
            val (path, name) = withContext(Dispatchers.IO) {
                copyToCache(uri) to (queryFileName(uri) ?: "binary.so")
            }

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

    private fun copyToCache(uri: Uri): String? {
        return try {
            val name = queryFileName(uri) ?: "binary.so"
            val dest = File(cacheDir, name)
            contentResolver.openInputStream(uri)?.use { input ->
                FileOutputStream(dest).use { output -> input.copyTo(output) }
            }
            dest.absolutePath
        } catch (e: Exception) { null }
    }

    private fun queryFileName(uri: Uri): String? {
        return contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val col = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (cursor.moveToFirst() && col >= 0) cursor.getString(col) else null
        }
    }
}
