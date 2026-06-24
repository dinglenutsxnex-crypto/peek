package com.kyhsgeekcode.disassembler.viewmodel

import android.app.Application
import android.content.Intent
import android.graphics.BitmapFactory
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Parcelable
import android.provider.OpenableColumns
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import at.pollaknet.api.facile.FacileReflector
import at.pollaknet.api.facile.renderer.ILAsmRenderer
import at.pollaknet.api.facile.symtab.symbols.Method
import com.kyhsgeekcode.FileExtensions
import com.kyhsgeekcode.TAG
import com.kyhsgeekcode.disassembler.*
import com.kyhsgeekcode.disassembler.exporting.buildProjectExportFileName
import com.kyhsgeekcode.disassembler.exporting.copyFileToDocument
import com.kyhsgeekcode.disassembler.project.ProjectDataStorage
import com.kyhsgeekcode.disassembler.project.ProjectManager
import com.kyhsgeekcode.disassembler.project.ProjectOpenAction
import com.kyhsgeekcode.disassembler.project.models.ProjectModel
import com.kyhsgeekcode.disassembler.project.models.ProjectSourceDescriptor
import com.kyhsgeekcode.disassembler.project.models.ProjectSourceKind
import com.kyhsgeekcode.disassembler.project.models.ProjectType
import com.kyhsgeekcode.disassembler.project.determineProjectOpenAction
import com.kyhsgeekcode.disassembler.ui.FileDrawerTreeItem
import com.kyhsgeekcode.disassembler.ui.TabData
import com.kyhsgeekcode.disassembler.ui.TabKind
import com.kyhsgeekcode.disassembler.ui.tabs.*
import com.kyhsgeekcode.filechooser.model.FileItem
import com.kyhsgeekcode.filechooser.model.FileItemApp
import com.kyhsgeekcode.filechooser.NewFileChooserActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import timber.log.Timber
import java.io.File
import java.io.IOException
import java.util.*
import kotlin.collections.ArrayList
import kotlin.collections.HashMap
import kotlin.math.max
import kotlin.math.min

internal data class OpenedProjectWorkspaceState(
    val openedTabs: List<TabData>,
    val currentTabIndex: Int
)

internal fun openedProjectWorkspaceState(
    previousTabs: List<TabData>,
    previousCurrentTabIndex: Int
): OpenedProjectWorkspaceState {
    val defaultTabs = listOf(TabData("Overview", TabKind.ProjectOverview))
    if (previousCurrentTabIndex == 0 && previousTabs == defaultTabs) {
        return OpenedProjectWorkspaceState(
            openedTabs = previousTabs,
            currentTabIndex = previousCurrentTabIndex
        )
    }
    return OpenedProjectWorkspaceState(
        openedTabs = defaultTabs,
        currentTabIndex = 0
    )
}

sealed class ShowSearchForStringsDialog {
    object NotShown : ShowSearchForStringsDialog()
    data class Shown(val notice: String?) : ShowSearchForStringsDialog()
}

class MainViewModel(application: Application) : AndroidViewModel(application) {
    sealed class Event {
        object NavigateToSettings : Event()
        data class StartProgress(val dummy: Unit = Unit) : Event()
        data class FinishProgress(val dummy: Unit = Unit) : Event()
        data class AlertError(val text: String) : Event()

        data class ShowSnackBar(val text: String) : Event()

        data class ShowToast(val text: String) : Event()
    }


    private val eventChannel = Channel<Event>(Channel.BUFFERED)
    val eventsFlow = eventChannel.receiveAsFlow()

    private val _currentTabIndex = MutableStateFlow(0)
    val currentTabIndex = _currentTabIndex as StateFlow<Int>

    private val _askCopy = MutableStateFlow(false)
    val askCopy = _askCopy as StateFlow<Boolean>

    private val _file = MutableStateFlow(File("/"))
    val file = _file as StateFlow<File>

    private val _nativeFile = MutableStateFlow<File?>(null)
    val nativeFile = _nativeFile as StateFlow<File?>

    private val _projectType = MutableStateFlow(ProjectType.UNKNOWN)
    val projectType = _projectType as StateFlow<String>

    private val _openAsProject = MutableStateFlow(false)
    val openAsProject = _openAsProject as StateFlow<Boolean>

    private val _selectedFilePath = MutableStateFlow("")
    val selectedFilePath = _selectedFilePath as StateFlow<String>

    private val _currentProject = MutableStateFlow<ProjectModel?>(null)
    val currentProject = _currentProject as StateFlow<ProjectModel?>

    private val _fileDrawerRootNode = MutableStateFlow<FileDrawerTreeItem?>(null)
    val fileDrawerRootNode = _fileDrawerRootNode as StateFlow<FileDrawerTreeItem?>

    private val _showSearchForStrings =
        MutableStateFlow<ShowSearchForStringsDialog>(ShowSearchForStringsDialog.NotShown)
    val showSearchForStringsDialog = _showSearchForStrings as StateFlow<ShowSearchForStringsDialog>

    private val _openedTabs =
        MutableStateFlow(listOf(TabData("Overview", TabKind.ProjectOverview)))
    val openedTabs = _openedTabs as StateFlow<List<TabData>>

    private val tabDataMap = HashMap<TabData, PreparedTabData>()

    //  FileDrawerTreeItem(pm.rootFile, 0)

    init {
        viewModelScope.launch {
            currentProject.filterNotNull().collect { pm ->
                _fileDrawerRootNode.value = FileDrawerTreeItem(pm.rootFile, 0)
            }
        }
    }

    fun onSelectIntent(intent: Intent) {
        Timber.d("onActivityResultOk")
        when (val selection = resolveIncomingSelection(intent)) {
            is IncomingSelection.CompactFile -> {
                _openAsProject.value = selection.openAsProject
                onSelectFilePayload(selection.payload)
            }

            is IncomingSelection.UriSelection -> {
                _openAsProject.value = selection.openAsProject
                onSelectUri(selection.uri, selection.displayName)
            }

            null -> return
        }
    }

    private fun onSelectFilePayload(payload: SelectedFileIntentPayload) {
        val selectedFile = File(payload.filePath)
        when (val action = determineProjectOpenAction(selectedFile, _openAsProject.value)) {
            ProjectOpenAction.PromptCopy -> {
                _file.value = selectedFile
                _nativeFile.value = payload.nativeFilePath?.let(::File)
                _projectType.value = payload.projectType
                _askCopy.value = true
            }

            is ProjectOpenAction.OpenExistingProject -> {
                openExistingProject(action.projectInfoFile)
            }

            is ProjectOpenAction.ImportProjectArchive -> {
                importProjectArchive(action.archiveFile)
            }
        }
    }

    private fun openExistingProject(projectInfoFile: File) {
        viewModelScope.launch {
            eventChannel.send(Event.StartProgress())
            try {
                val project = withContext(Dispatchers.IO) {
                    ProjectManager.openProject(projectInfoFile.absolutePath)
                }
                applyOpenedProject(project)
            } catch (e: Exception) {
                eventChannel.send(Event.AlertError("Failed to open project"))
            }
            eventChannel.send(Event.FinishProgress())
        }
    }

    private fun importProjectArchive(archiveFile: File) {
        viewModelScope.launch {
            eventChannel.send(Event.StartProgress())
            try {
                val project = withContext(Dispatchers.IO) {
                    ProjectManager.import(archiveFile)
                }
                applyOpenedProject(project)
            } catch (e: Exception) {
                eventChannel.send(Event.AlertError("Failed to import project"))
            }
            eventChannel.send(Event.FinishProgress())
        }
    }

    private fun onSelectUri(uri: Uri, displayName: String? = null) {
        if (uri.scheme == "content") {
            try {
                val app = getApplication<Application>()
                app.contentResolver.openInputStream(uri).use { inStream ->
                    requireNotNull(inStream) { "Failed to open content URI: $uri" }
                    val fileName = resolveImportedFileName(app, uri, displayName)
                    val file = resolveImportedDestinationFile(
                        app.filesDir.resolve("imports"),
                        fileName
                    )
                    file.parentFile?.mkdirs()
                    file.outputStream().use { fileOut ->
                        inStream.copyTo(fileOut)
                    }
                    val project = when (
                        val action = determineImportedUriAction(file, uri.toString())
                    ) {
                        is ImportedUriAction.CreateProject -> ProjectManager.newProject(
                            action.importedFile,
                            ProjectType.UNKNOWN,
                            action.importedFile.name,
                            true,
                            action.sourceDescriptor
                        )

                        is ImportedUriAction.ImportProjectArchive -> ProjectManager.import(action.archiveFile)
                    }
                    applyOpenedProject(project)
                }
            } catch (e: Exception) {
                viewModelScope.launch {
                    eventChannel.send(Event.FinishProgress())
                    eventChannel.send(Event.AlertError("Failed to create project"))
                }
            }
        }
    }

    fun onCopy(copy: Boolean) {
        _askCopy.value = false
        CoroutineScope(Dispatchers.Main).launch {
            eventChannel.send(Event.StartProgress())
            try {
                val project = withContext(Dispatchers.IO) {
                    onClickCopyDialog(copy)
                }
                applyOpenedProject(project)
            } catch (e: Exception) {
                eventChannel.send(Event.AlertError("Failed to create project"))
            }
            eventChannel.send(Event.FinishProgress())
        }
    }

    private fun onClickCopyDialog(
        copy: Boolean
    ): ProjectModel {
        val project =
            ProjectManager.newProject(file.value, projectType.value, file.value.name, copy)
        if (copy) {
            copyNativeDirToProject(nativeFile.value, project)
        }
        return project
    }

    fun onOpenDrawerItem(item: FileDrawerTreeItem) {
        openDrawerItem(item)
    }

    fun openAsHex() {
        val relPath = getCurrentRelPath() ?: return
//        val relPath: String = ProjectManager.getRelPath(absPath)
        val tabData = TabData("$relPath AS HEX", TabKind.Hex(relPath))
        openNewTab(tabData)
    }

    private fun getCurrentRelPath(): String? {
        return when (val tk = openedTabs.value[currentTabIndex.value].tabKind) {
            is TabKind.Binary -> tk.relPath
            is TabKind.AnalysisResult -> null
            is TabKind.Apk -> tk.relPath
            is TabKind.Archive -> tk.relPath
            is TabKind.Dex -> tk.relPath
            is TabKind.DotNet -> tk.relPath
            is TabKind.FoundString -> null
            is TabKind.Hex -> null
            is TabKind.Image -> tk.relPath
            is TabKind.Log -> null
            is TabKind.ProjectOverview -> null
            is TabKind.Text -> null
        }
    }

    private fun openDrawerItem(item: FileDrawerTreeItem) {
        Timber.d("Opening item: ${item.caption}")
        val tabData = createTabData(item)
        openNewTab(tabData)
    }

    @ExperimentalUnsignedTypes
    private fun prepareTabData(tabData: TabData) {
        val data = when (val tabKind = tabData.tabKind) {
            is TabKind.AnalysisResult -> AnalysisTabData(tabKind)
            is TabKind.Apk -> TODO()
            is TabKind.Archive -> TODO()
            is TabKind.Binary -> BinaryTabData(tabKind, viewModelScope)
            is TabKind.Dex -> TODO() // DexTabData(tabKind)
            is TabKind.DotNet ->  TODO()
            is TabKind.Image -> ImageTabData(
                tabKind,
                getApplication<Application>().applicationContext.resources
            )
            is TabKind.ProjectOverview -> PreparedTabData()
            is TabKind.Text -> TextTabData(tabKind)
            is TabKind.FoundString -> StringTabData(tabKind)
            is TabKind.Hex -> HexTabData(tabKind)
            is TabKind.Log -> TODO()
        }
        viewModelScope.launch {
            data.prepare()
        }
        tabDataMap[tabData] = data
    }

    fun <T : PreparedTabData> getTabData(key: TabData): T {
        return (tabDataMap[key] as T)
    }

    fun closeCurrentFile() {
        // free memory and remove from list
        val curIdx = currentTabIndex.value
        if (openedTabs.value.size > 1) {
            _currentTabIndex.value = max(currentTabIndex.value - 1, 0)
            val tabData = openedTabs.value[curIdx]
            tabDataMap.remove(tabData)
            _openedTabs.value = openedTabs.value - tabData
        }
    }

    fun isBinaryTab(): Boolean {
        return openedTabs.value[currentTabIndex.value].tabKind is TabKind.Binary
    }

    fun setCurrentTabByIndex(index: Int) {
        _currentTabIndex.value = index
    }

    fun getCurrentTabData(): PreparedTabData? {
        return tabDataMap[openedTabs.value[currentTabIndex.value]]
    }

    fun searchForStrings() {
        Timber.d("Will be shown strings dialog")
        val notice = getCurrentRelPath()
            ?.let { ProjectDataStorage.resolveToRead(it)?.length() }
            ?.let { buildStringSearchDialogNotice(it) }
        _showSearchForStrings.value = ShowSearchForStringsDialog.Shown(notice)
    }

    fun analyze() {
        val relPath = getCurrentRelPath() ?: return

        val tabData = TabData(
            newCaptionFromCurrent("Analysis"),
            TabKind.AnalysisResult(relPath)
        )
        openNewTab(tabData)
    }

    fun dismissSearchForStringsDialog() {
        _showSearchForStrings.value = ShowSearchForStringsDialog.NotShown
    }

    suspend fun exportCurrentProject(destinationUri: Uri): Result<Unit> {
        val project = currentProject.value ?: return Result.failure(
            IllegalStateException("No project is open")
        )
        return runCatching {
            val application = getApplication<Application>()
            val tempArchive = withContext(Dispatchers.IO) {
                val exportDir = application.cacheDir.resolve("exports")
                exportDir.mkdirs()
                val outFile = exportDir.resolve(buildProjectExportFileName(project.name))
                if (ProjectManager.exportArchive(project, outFile).not()) {
                    throw IOException("Failed to export project archive")
                }
                outFile
            }
            withContext(Dispatchers.IO) {
                copyFileToDocument(application.contentResolver, tempArchive, destinationUri)
            }
        }
    }

    fun reallySearchForStrings(from: String, to: String) {
        _showSearchForStrings.value = ShowSearchForStringsDialog.NotShown
        val f = from.toIntOrNull() ?: return
        val t = to.toIntOrNull() ?: return
        val relPath = getCurrentRelPath() ?: return

        val tabData = TabData(
            newCaptionFromCurrent("String"),
            TabKind.FoundString(relPath, min(f, t)..max(f, t))
        )
        openNewTab(tabData)
    }

    private fun newCaptionFromCurrent(with: String): String {
        return openedTabs.value[currentTabIndex.value].title.replaceAfter("as ", with)
    }

    private fun applyOpenedProject(project: ProjectModel) {
        val workspaceState = openedProjectWorkspaceState(
            previousTabs = _openedTabs.value,
            previousCurrentTabIndex = _currentTabIndex.value
        )
        ProjectDataStorage.clear()
        tabDataMap.clear()
        _openedTabs.value = workspaceState.openedTabs
        _currentTabIndex.value = workspaceState.currentTabIndex
        _showSearchForStrings.value = ShowSearchForStringsDialog.NotShown
        _selectedFilePath.value = project.sourceFilePath
        _currentProject.value = project
    }

    private fun openNewTab(tabData: TabData) {
        prepareTabData(tabData)
        val newList = ArrayList<TabData>()
        newList.addAll(openedTabs.value)
        newList.add(tabData)
        _openedTabs.value = newList
    }
}

internal fun sanitizeImportedFileName(displayName: String?): String {
    val normalized = displayName
        ?.trim()
        ?.takeIf { it.isNotEmpty() }
        ?.replace(Regex("""[/\\]+"""), "_")
    return normalized ?: "openDirect"
}

internal sealed class ImportedUriAction {
    data class CreateProject(
        val importedFile: File,
        val sourceDescriptor: ProjectSourceDescriptor
    ) : ImportedUriAction()

    data class ImportProjectArchive(val archiveFile: File) : ImportedUriAction()
}

internal fun determineImportedUriAction(importedFile: File, sourceUriLocation: String): ImportedUriAction {
    return when (val action = determineProjectOpenAction(importedFile, openAsProject = true)) {
        is ProjectOpenAction.ImportProjectArchive -> ImportedUriAction.ImportProjectArchive(action.archiveFile)
        is ProjectOpenAction.OpenExistingProject,
        ProjectOpenAction.PromptCopy -> ImportedUriAction.CreateProject(
            importedFile = importedFile,
            sourceDescriptor = ProjectSourceDescriptor(
                ProjectSourceKind.CONTENT_URI,
                sourceUriLocation
            )
        )
    }
}

internal fun resolveImportedDestinationFile(importsDir: File, displayName: String?): File {
    val sanitizedName = sanitizeImportedFileName(displayName)
    var candidate = importsDir.resolve(sanitizedName)
    if (!candidate.exists()) {
        return candidate
    }

    val baseName = candidate.nameWithoutExtension.ifBlank { candidate.name }
    val extensionSuffix = candidate.extension.takeIf { it.isNotBlank() }?.let { ".$it" } ?: ""
    var index = 1
    while (candidate.exists()) {
        candidate = importsDir.resolve("${baseName}_$index$extensionSuffix")
        index++
    }
    return candidate
}

private fun resolveImportedFileName(
    app: Application,
    uri: Uri,
    suggestedDisplayName: String?
): String {
    val displayName = suggestedDisplayName
        ?: app.contentResolver.query(
            uri,
            arrayOf(OpenableColumns.DISPLAY_NAME),
            null,
            null,
            null
        )?.use { cursor ->
            val displayNameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (displayNameIndex >= 0 && cursor.moveToFirst()) {
                cursor.getString(displayNameIndex)
            } else {
                null
            }
        }
        ?: uri.lastPathSegment
    return sanitizeImportedFileName(displayName)
}

private inline fun <reified T : Parcelable> Intent.parcelableExtraCompat(key: String): T? {
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        getParcelableExtra(key, T::class.java)
    } else {
        @Suppress("DEPRECATION")
        getParcelableExtra(key)
    }
}

private inline fun <reified T : Parcelable> Bundle?.parcelableExtraCompat(key: String): T? {
    return if (this == null) {
        null
    } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        getParcelable(key, T::class.java)
    } else {
        @Suppress("DEPRECATION")
        getParcelable(key)
    }
}

internal data class SelectedFileIntentPayload(
    val filePath: String,
    val nativeFilePath: String?,
    val projectType: String
)

internal sealed class IncomingSelection {
    data class CompactFile(
        val payload: SelectedFileIntentPayload,
        val openAsProject: Boolean
    ) : IncomingSelection()

    data class UriSelection(
        val uri: Uri,
        val displayName: String?,
        val openAsProject: Boolean
    ) : IncomingSelection()
}

internal fun resolveIncomingSelection(intent: Intent): IncomingSelection? {
    return resolveIncomingSelection(
        openAsProject = intent.getBooleanExtra("openProject", false),
        filePath = intent.getStringExtra(NewFileChooserActivity.EXTRA_FILE_PATH),
        nativeFilePath = intent.getStringExtra(NewFileChooserActivity.EXTRA_NATIVE_FILE_PATH),
        projectType = intent.getStringExtra(NewFileChooserActivity.EXTRA_PROJECT_TYPE),
        uri = intent.parcelableExtraCompat("uri"),
        extraStreamUri = intent.extras.parcelableExtraCompat(Intent.EXTRA_STREAM),
        displayName = intent.getStringExtra("displayName")
    )
}

internal fun resolveIncomingSelection(
    openAsProject: Boolean,
    filePath: String?,
    nativeFilePath: String?,
    projectType: String?,
    uri: Uri?,
    extraStreamUri: Uri?,
    displayName: String?
): IncomingSelection? {
    val selectedFilePayload = selectedFileIntentPayload(
        filePath = filePath,
        nativeFilePath = nativeFilePath,
        projectType = projectType
    )
    if (selectedFilePayload != null) {
        return IncomingSelection.CompactFile(selectedFilePayload, openAsProject)
    }
    val incomingUri = uri ?: extraStreamUri ?: return null
    return IncomingSelection.UriSelection(
        uri = incomingUri,
        displayName = displayName,
        openAsProject = openAsProject
    )
}

internal fun selectedFileIntentPayload(intent: Intent): SelectedFileIntentPayload? {
    return selectedFileIntentPayload(
        filePath = intent.getStringExtra(NewFileChooserActivity.EXTRA_FILE_PATH),
        nativeFilePath = intent.getStringExtra(NewFileChooserActivity.EXTRA_NATIVE_FILE_PATH),
        projectType = intent.getStringExtra(NewFileChooserActivity.EXTRA_PROJECT_TYPE)
    )
}

internal fun selectedFileIntentPayload(
    filePath: String?,
    nativeFilePath: String?,
    projectType: String?
): SelectedFileIntentPayload? {
    val resolvedFilePath = filePath ?: return null
    return SelectedFileIntentPayload(
        filePath = resolvedFilePath,
        nativeFilePath = nativeFilePath,
        projectType = projectType ?: ProjectType.UNKNOWN
    )
}


private fun createTabData(item: FileDrawerTreeItem): TabData {
    var title = "${item.caption} as ${item.type}"
//        val rootPath = ProjectManager.getOriginal("").absolutePath
    if (item.type == FileDrawerTreeItem.DrawerItemType.METHOD) {
        val reflector = (item.tag as Array<*>)[0] as FacileReflector
        val method = (item.tag as Array<*>)[1] as Method
        val renderedStr = ILAsmRenderer(reflector).render(method)
        val key = "${method.owner.name}.${method.name}_${method.methodSignature}"
        ProjectDataStorage.putFileContent(key, renderedStr.encodeToByteArray())
        return TabData(key, TabKind.Text(key))
    }
    val abspath = (item.tag as String)
//        Log.d(TAG, "rootPath:${rootPath}")
    Timber.d("absPath:$abspath")
    val ext = File(abspath).extension.lowercase(Locale.getDefault())
    val relPath = ProjectManager.getRelPathOrNull(abspath)
        ?: return buildUnavailablePathTabData(item.caption, abspath)
//        if (abspath.length > rootPath.length)
//            relPath = abspath.substring(rootPath.length+2)
//        else
//            relPath = ""
    Timber.d("relPath:$relPath")
    val tabkind: TabKind = when (item.type) {
        FileDrawerTreeItem.DrawerItemType.ARCHIVE -> TabKind.Archive(relPath)
        FileDrawerTreeItem.DrawerItemType.APK -> TabKind.Apk(relPath)
        FileDrawerTreeItem.DrawerItemType.NORMAL -> {
            Timber.d("ext:$ext")
            if (FileExtensions.textFileExts.contains(ext)) {
                title = "${item.caption} as Text"
                TabKind.Text(relPath)
            } else {
                val file = File(abspath)
                try {
                    (BitmapFactory.decodeStream(file.inputStream())
                        ?: throw Exception()).recycle()
                    TabKind.Image(relPath)
                } catch (e: Exception) {
                    TabKind.Binary(relPath)
                }
            }
        }
        FileDrawerTreeItem.DrawerItemType.BINARY -> TabKind.Binary(relPath)
        FileDrawerTreeItem.DrawerItemType.PE -> TabKind.Binary(relPath)
        FileDrawerTreeItem.DrawerItemType.PE_IL -> TabKind.DotNet(relPath)
        FileDrawerTreeItem.DrawerItemType.DEX -> TabKind.Dex(relPath)
        /*FileDrawerTreeItem.DrawerItemType.DISASSEMBLY -> TabKind.BinaryDisasm(
            relPath,
            ViewMode.Text
        )*/
        else -> throw Exception()
    }

    return TabData(title, tabkind)
}

private fun buildUnavailablePathTabData(caption: String, abspath: String): TabData {
    val key = "unavailable:${abspath.hashCode()}"
    ProjectDataStorage.putFileContent(
        key,
        "The selected entry is no longer inside the current project:\n$abspath".encodeToByteArray()
    )
    return TabData("$caption unavailable", TabKind.Text(key))
}

fun fileItemTypeToProjectType(fileItem: FileItem): String {
    if (fileItem is FileItemApp)
        return ProjectType.APK
    return ProjectType.UNKNOWN
}

fun copyNativeDirToProject(nativeFile: File?, project: ProjectModel) {
    if (nativeFile != null && nativeFile.exists() && nativeFile.canRead()) {
        val targetFolder = project.sourceLibrariesDirectory
        targetFolder.mkdirs()
        var targetFile = targetFolder.resolve(nativeFile.name)
        var i = 0
        while (targetFile.exists()) {
            targetFile = File(targetFile.absolutePath + "_extracted_$i.so")
            i++
        }
        // FileUtils.copyDirectory(nativeFile, targetFile)
        copyDirectory(nativeFile, targetFile)
    }
}
