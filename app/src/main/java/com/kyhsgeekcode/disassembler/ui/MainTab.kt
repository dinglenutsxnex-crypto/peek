package com.kyhsgeekcode.disassembler.ui

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.widget.Toast
import androidx.activity.compose.ManagedActivityResultLauncher
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import com.kyhsgeekcode.disassembler.R
import com.kyhsgeekcode.disassembler.exporting.buildProjectExportFileName
import com.kyhsgeekcode.disassembler.importing.DefaultImportEntryPointCatalog
import com.kyhsgeekcode.disassembler.importing.ImportEntryPoint
import com.kyhsgeekcode.disassembler.importing.legacyPermissionsForImportEntryPoint
import com.kyhsgeekcode.disassembler.preference.PowerUserModeSettings
import com.kyhsgeekcode.disassembler.viewmodel.MainViewModel
import com.kyhsgeekcode.filechooser.NewFileChooserActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun ProjectOverview(viewModel: MainViewModel) {
    val context = LocalContext.current
    val lifecycleOwner = context as? LifecycleOwner
    val scope = androidx.compose.runtime.rememberCoroutineScope()
    var powerUserModeEnabled by remember {
        mutableStateOf(PowerUserModeSettings.isEnabled(context))
    }
    val currentProject by viewModel.currentProject.collectAsState()

    val advancedImportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) {
        if (it.resultCode == Activity.RESULT_OK) {
            val i = it.data
            i?.run {
                viewModel.onSelectIntent(this)
            }
        }
    }
    val legacyPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { grantResults ->
        if (grantResults.values.all { it }) {
            launchAdvancedImportActivity(context, advancedImportLauncher)
        } else {
            Toast.makeText(context, R.string.permission_needed, Toast.LENGTH_LONG).show()
        }
    }
    val safImportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { selectedUri ->
        if (selectedUri != null) {
            try {
                context.contentResolver.takePersistableUriPermission(
                    selectedUri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION
                )
            } catch (_: SecurityException) {
            }
            viewModel.onSelectIntent(
                Intent().apply {
                    putExtra("uri", selectedUri)
                    putExtra("openProject", false)
                }
            )
        }
    }
    val exportProjectLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/zip")
    ) { destinationUri ->
        if (destinationUri != null) {
            scope.launch {
                val result = viewModel.exportCurrentProject(destinationUri)
                val message = if (result.isSuccess) {
                    context.getString(R.string.project_exported)
                } else {
                    context.getString(R.string.fail_exportzip)
                }
                withContext(Dispatchers.Main.immediate) {
                    Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    val askCopy = viewModel.askCopy.collectAsState()
    val visibleEntryPoints = remember(powerUserModeEnabled) {
        DefaultImportEntryPointCatalog.visibleEntryPoints(powerUserModeEnabled)
    }

    DisposableEffect(lifecycleOwner, context) {
        if (lifecycleOwner == null) {
            onDispose {}
        } else {
            val observer = object : DefaultLifecycleObserver {
                override fun onResume(owner: LifecycleOwner) {
                    powerUserModeEnabled = PowerUserModeSettings.isEnabled(context)
                }
            }
            lifecycleOwner.lifecycle.addObserver(observer)
            onDispose {
                lifecycleOwner.lifecycle.removeObserver(observer)
            }
        }
    }

    Column(
        Modifier
            .fillMaxSize()
            .padding(10.dp)
    ) {
        Text(text = stringResource(id = R.string.main_select_source_guide))
        Row(Modifier.fillMaxWidth()) {
            for (entryPoint in visibleEntryPoints) {
                Button(
                    modifier = Modifier
                        .padding(end = 8.dp)
                        .testTag(importEntryPointTestTag(entryPoint)),
                    onClick = {
                        launchImportEntryPoint(
                            entryPoint,
                            context = context,
                            safImportLauncher = safImportLauncher,
                            advancedImportLauncher = advancedImportLauncher,
                            legacyPermissionLauncher = legacyPermissionLauncher
                        )
                    }
                ) {
                    Text(text = stringResource(id = entryPoint.labelRes))
                }
            }
        }
        if (currentProject != null) {
            Button(
                modifier = Modifier
                    .padding(top = 12.dp)
                    .testTag(MainTestTags.EXPORT_PROJECT_BUTTON),
                onClick = {
                    exportProjectLauncher.launch(
                        buildProjectExportFileName(currentProject!!.name)
                    )
                }
            ) {
                Text(text = stringResource(id = R.string.export_project))
            }
        }
    }

    if (askCopy.value) {
        AlertDialog(
            onDismissRequest = {
                // viewModel.onCopyReply(false)
            },
            title = {
                Text(text = "Copy?")
            },
            text = {
                Text("Copy?")
            },
            confirmButton = {
                Row(
                    modifier = Modifier.padding(all = 8.dp),
                    horizontalArrangement = Arrangement.Center
                ) {
                    Button(
                        modifier = Modifier
                            .weight(1f)
                            .testTag(MainTestTags.COPY_DIALOG_NO_BUTTON),
                        onClick = { viewModel.onCopy(false) }
                    ) {
                        Text("No")
                    }
                    Button(
                        modifier = Modifier
                            .weight(1f)
                            .testTag(MainTestTags.COPY_DIALOG_YES_BUTTON),
                        onClick = { viewModel.onCopy(true) }
                    ) {
                        Text("Yes")
                    }
                }
            }
        )
    }
}

private fun importEntryPointTestTag(entryPoint: ImportEntryPoint): String {
    return when (entryPoint) {
        ImportEntryPoint.SafImport -> MainTestTags.IMPORT_SAF_BUTTON
        ImportEntryPoint.AdvancedImport -> MainTestTags.IMPORT_ADVANCED_BUTTON
    }
}

private fun launchImportEntryPoint(
    entryPoint: ImportEntryPoint,
    context: android.content.Context,
    safImportLauncher: ManagedActivityResultLauncher<Array<String>, android.net.Uri?>,
    advancedImportLauncher: ManagedActivityResultLauncher<Intent, androidx.activity.result.ActivityResult>,
    legacyPermissionLauncher: ManagedActivityResultLauncher<Array<String>, Map<String, @JvmSuppressWildcards Boolean>>
) {
    when (entryPoint) {
        ImportEntryPoint.SafImport -> safImportLauncher.launch(arrayOf("*/*"))
        ImportEntryPoint.AdvancedImport -> {
            val requiredPermissions =
                legacyPermissionsForImportEntryPoint(entryPoint, Build.VERSION.SDK_INT)
            if (requiredPermissions.isNotEmpty() && !hasAllPermissions(context, requiredPermissions)) {
                legacyPermissionLauncher.launch(requiredPermissions)
            } else {
                launchAdvancedImportActivity(context, advancedImportLauncher)
            }
        }
    }
}

private fun launchAdvancedImportActivity(
    context: android.content.Context,
    advancedImportLauncher: ManagedActivityResultLauncher<Intent, androidx.activity.result.ActivityResult>
) {
    val intent = Intent(context, NewFileChooserActivity::class.java).apply {
        putExtra(NewFileChooserActivity.EXTRA_POWER_USER_MODE, true)
    }
    advancedImportLauncher.launch(intent)
}

private fun hasAllPermissions(
    context: android.content.Context,
    permissions: Array<String>
): Boolean {
    return permissions.all {
        ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED
    }
}
