package com.kyhsgeekcode.filechooser

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.util.Log
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.kyhsgeekcode.disassembler.ProgressHandler
import com.kyhsgeekcode.disassembler.databinding.ActivityNewFileChooserBinding
import com.kyhsgeekcode.disassembler.preference.PowerUserModeSettings
import com.kyhsgeekcode.disassembler.project.models.ProjectType
import com.kyhsgeekcode.disassembler.showYesNoDialog
import com.kyhsgeekcode.download
import com.kyhsgeekcode.filechooser.model.FileItem
import com.kyhsgeekcode.filechooser.model.FileItemApp
import com.tingyik90.snackprogressbar.SnackProgressBar
import com.tingyik90.snackprogressbar.SnackProgressBarManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.jsoup.Jsoup
import splitties.init.appCtx
import java.net.URL


class NewFileChooserActivity : AppCompatActivity(), ProgressHandler {
    companion object {
        const val EXTRA_POWER_USER_MODE = "power_user_mode"
        const val EXTRA_FILE_PATH = "selected_file_path"
        const val EXTRA_NATIVE_FILE_PATH = "selected_native_file_path"
        const val EXTRA_PROJECT_TYPE = "selected_project_type"
    }

    private var _binding: ActivityNewFileChooserBinding? = null
    private val binding get() = _binding!!
    private val powerUserMode by lazy {
        intent?.getBooleanExtra(EXTRA_POWER_USER_MODE, false) ?: false
    }
    val advancedImportOptions by lazy {
        PowerUserModeSettings.advancedImportOptions(this).copy(powerUserMode = powerUserMode)
    }

    private val snackProgressBarManager by lazy {
        SnackProgressBarManager(
            binding.fileChooserMainLayout,
            lifecycleOwner = this
        )
    }
    private val circularType = SnackProgressBar(SnackProgressBar.TYPE_HORIZONTAL, "Loading...")
        .setIsIndeterminate(false)
        .setAllowUserInput(false)
    private val indeterminate = SnackProgressBar(SnackProgressBar.TYPE_CIRCULAR, "Loading...")
        .setIsIndeterminate(true)
        .setAllowUserInput(false)
    lateinit var adapter: NewFileChooserAdapter
    private lateinit var linearLayoutManager: LinearLayoutManager
    val TAG = "NewFileChooserA"
    private val openDocumentLauncher =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { selectedUri ->
            if (selectedUri == null) {
                return@registerForActivityResult
            }
            grantReadPermission(selectedUri)
            val resultIntent = Intent().apply {
                putExtra("uri", selectedUri)
                putExtra("displayName", queryDisplayName(selectedUri))
                putExtra("openProject", false)
            }
            setResult(Activity.RESULT_OK, resultIntent)
            finish()
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        Log.v(TAG, "onCreate")
        super.onCreate(savedInstanceState)
        _binding = ActivityNewFileChooserBinding.inflate(layoutInflater)
        setContentView(binding.root)
        adapter = NewFileChooserAdapter(this, advancedImportOptions)
        lifecycleScope.launch {
            adapter.tryAddRootItems()
        }
        linearLayoutManager = LinearLayoutManager(this)
        binding.recyclerView.layoutManager = linearLayoutManager
        binding.recyclerView.adapter = adapter
        adapter.notifyDataSetChanged()
    }

    fun openAsProject(item: FileItem) {
        val resultIntent = selectedFileResultIntent(item).apply {
            putExtra("openProject", true)
        }
        setResult(Activity.RESULT_OK, resultIntent)
        finish()
    }

    fun openRaw(item: FileItem) {
        val resultIntent = selectedFileResultIntent(item).apply {
            putExtra("openProject", false)
        }
        setResult(Activity.RESULT_OK, resultIntent)
        finish()
    }

    override fun onBackPressed() {
        if (adapter.onBackPressedShouldFinish()) {
            finish()
        }
    }

    override fun publishProgress(current: Int, total: Int?, message: String?) {
        snackProgressBarManager.setProgress(current)
        if (total != null || message != null) {
            if (total != null)
                circularType.setProgressMax(total)
            if (message != null)
                circularType.setMessage(message)
            if (snackProgressBarManager.getLastShown() == null)
                snackProgressBarManager.show(
                    circularType,
                    SnackProgressBarManager.LENGTH_INDEFINITE
                )
            snackProgressBarManager.updateTo(circularType)
        }
    }

    override fun startProgress() {
        snackProgressBarManager.show(indeterminate, SnackProgressBarManager.LENGTH_INDEFINITE)
    }

    override fun finishProgress() {
        snackProgressBarManager.dismiss()
    }

    fun showOtherChooser() {
        openDocumentLauncher.launch(arrayOf("*/*"))
    }

    fun showZoo() {
        Toast.makeText(
            this,
            "Download a sample from the zoo and open it with this app",
            Toast.LENGTH_SHORT
        ).show()
        val url = "https://github.com/ytisf/theZoo/"
        val i = Intent(Intent.ACTION_VIEW)
        i.data = Uri.parse(url)
        startActivity(i)
        finish()
    }

    fun showHashSite(hash: String) {
        showYesNoDialog(
            this,
            "Danger alert",
            "The file you are trying to download may harm your device. Proceed?",
            { dlg, which ->
                val url = "https://infosec.cert-pa.it/analyze/$hash.html"
                val i = Intent(Intent.ACTION_VIEW)
                i.data = Uri.parse(url)
                startActivity(i)
                Toast.makeText(this, "Downloading...", Toast.LENGTH_SHORT).show()
                CoroutineScope(Dispatchers.IO).launch {
                    try {
                        val document = Jsoup.parse(URL(url), 30000)
                        val ipaddr = document.select("[rel=nofollow]").first()?.text()
                        Log.d(TAG, "ipaddr=$ipaddr")
                        val realAddr = ipaddr?.replace("hXXp", "http") ?: return@launch
                        Log.d(TAG, "RealAddr:$realAddr")
                        val targetFile = appCtx.filesDir.resolve("malwareSamples")
                        download(realAddr, targetFile)
                        withContext(Dispatchers.Main) {
                            Toast.makeText(
                                this@NewFileChooserActivity,
                                "Download success",
                                Toast.LENGTH_SHORT
                            ).show()
                        }
                        val resultIntent = Intent()
                        resultIntent.putExtra("malwareFile", targetFile)
                        setResult(Activity.RESULT_OK, resultIntent)
                        finish()
                    } catch (e: Exception) {
                        Log.e(TAG, "Failed downloading from $url", e)
                        withContext(Dispatchers.Main) {
                            Toast.makeText(
                                this@NewFileChooserActivity,
                                "Download failed",
                                Toast.LENGTH_SHORT
                            ).show()
                        }
                    }
                }
            },
            null
        )
    }

    private fun grantReadPermission(selectedUri: Uri) {
        try {
            contentResolver.takePersistableUriPermission(
                selectedUri,
                Intent.FLAG_GRANT_READ_URI_PERMISSION
            )
        } catch (e: SecurityException) {
            Log.w(TAG, "Persistable URI permission not available for $selectedUri", e)
        }
    }

    private fun queryDisplayName(selectedUri: Uri): String? {
        contentResolver.query(
            selectedUri,
            arrayOf(OpenableColumns.DISPLAY_NAME),
            null,
            null,
            null
        )?.use { cursor ->
            val displayNameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (displayNameIndex >= 0 && cursor.moveToFirst()) {
                return cursor.getString(displayNameIndex)
            }
        }
        return null
    }

    private fun selectedFileResultIntent(item: FileItem): Intent {
        val file = requireNotNull(item.file) { "Cannot return chooser result without a backing file" }
        return Intent().apply {
            putExtra(EXTRA_FILE_PATH, file.absolutePath)
            putExtra(EXTRA_PROJECT_TYPE, projectTypeFor(item))
            if (item is FileItemApp) {
                putExtra(EXTRA_NATIVE_FILE_PATH, item.nativeFile.absolutePath)
            }
        }
    }

    private fun projectTypeFor(item: FileItem): String {
        return if (item is FileItemApp) {
            ProjectType.APK
        } else {
            ProjectType.UNKNOWN
        }
    }

}
