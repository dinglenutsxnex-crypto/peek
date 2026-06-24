package com.kyhsgeekcode.disassembler.project

import android.content.Context
import android.util.Log
import com.kyhsgeekcode.disassembler.Logger
import com.kyhsgeekcode.disassembler.exporting.buildProjectExportFileName
import com.kyhsgeekcode.disassembler.copyDirectory
import com.kyhsgeekcode.disassembler.project.models.ProjectModel
import com.kyhsgeekcode.disassembler.project.models.ProjectSourceDescriptor
import com.kyhsgeekcode.disassembler.project.models.ProjectSourceKind
import com.kyhsgeekcode.extractZip
import com.kyhsgeekcode.isAccessible
import com.kyhsgeekcode.saveAsZip
import com.kyhsgeekcode.toValidFileName
import kotlinx.serialization.SerializationException
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.json.JSONException
import splitties.init.appCtx
import java.io.File
import java.io.IOException
import java.util.zip.ZipFile

/**
 * the list of paths of project_info.json is saved to a SharedPreference.
 * project_info.json files are usually found in externalStorageDir.
 * project_info.json files point to the actual target files and project types.
 * <li> export: package needed files including target files and analysis files into a zip file.
 * <li> import: unpack the file back.
 * <li> save: save the diffs to the project
 * <li> new: create a new project_info.json file to default directory(externalStorageDir) and registers it.
 * <li> open: open the project and load the info.
 */

object ProjectManager {
    val TAG = "ProjectManager"

    val projectModels: MutableMap<String, ProjectModel> = HashMap()
    val projectModelToPath: MutableMap<ProjectModel, String> = HashMap()
    val projectPaths: MutableSet<String> = HashSet()
    val rootdir = appCtx.getExternalFilesDir(null)!!.resolve("projects/")
    var currentProject: ProjectModel? = null

    init {
        val sharedPreference = appCtx.getSharedPreferences("ProjectManager", Context.MODE_PRIVATE)
        val paths = sharedPreference.getStringSet("projectsPaths", setOf(""))!!
        projectPaths.clear()
        for (path in paths) {
            val file = File(path)
            if (!file.isAccessible())
                continue
            projectPaths.add(path)
            val jsonString = file.inputStream().bufferedReader().use { it.readText() }
            projectModels[path] = Json.decodeFromString(ProjectModel.serializer(), jsonString)
            projectModelToPath[projectModels[path]!!] = path
        }

        rootdir.mkdirs()
    }

    /**
     * Save the changed project list and info.
     * MUST be called to commit changes.
     */
    fun close() {
        projectPaths.clear()
        for (projectModel in projectModels) {
            val jsonString = Json.encodeToString(ProjectModel.serializer(), projectModel.value)
            val file = File(projectModel.key)
            file.outputStream().bufferedWriter().use { it.write(jsonString) }
            projectPaths.add(file.absolutePath)
        }
        val sharedPreference = appCtx.getSharedPreferences("ProjectManager", Context.MODE_PRIVATE)
        sharedPreference.edit().putStringSet("projectsPaths", projectPaths).apply()
    }

    /**
     * Creates a ProjectModel and registers the project_info.json path.
     *
     * @param targetFileOrFolder the target file or directory to analyze
     * @param projectType should be ProjectType
     * @param projectName the name of project. should be valid file name
     * @author KYHSGeekCode
     * @return the project model created
     * @throws IOException
     */
    @Throws(IOException::class)
    fun newProject(
        targetFileOrFolder: File,
        projectType: String,
        projectName: String,
        copy: Boolean = true,
        sourceDescriptor: ProjectSourceDescriptor = ProjectSourceDescriptor(
            ProjectSourceKind.FILE_PATH,
            targetFileOrFolder.absolutePath
        )
    ): ProjectModel {
//        require(if (useDefault) true else file.isDirectory)
        val projectModel: ProjectModel
        val projectFolder = rootdir.resolve(projectName.toValidFileName())
        projectFolder.delete()
        projectFolder.mkdirs()
        val projectInfoFile = projectFolder.resolve("project_info.json")
        val genFolder = projectFolder.resolve("generated")
        val origFolder = projectFolder.resolve("original")
        origFolder.mkdirs()
        genFolder.mkdirs()
        val determinedSourceFolder: File
        if (copy) {
            val copyTargetFileOrFolder = origFolder.resolve(targetFileOrFolder.name)
            if (!targetFileOrFolder.isDirectory && targetFileOrFolder != copyTargetFileOrFolder) {
                // FileUtils.copyFile(targetFileOrFolder, copyTargetFileOrFolder)
                targetFileOrFolder.copyTo(copyTargetFileOrFolder, true)
            } else if (targetFileOrFolder != copyTargetFileOrFolder) {
//                FileUtils.copyDirectory(targetFileOrFolder, copyTargetFileOrFolder)
                copyDirectory(targetFileOrFolder, copyTargetFileOrFolder)
            }
            determinedSourceFolder = copyTargetFileOrFolder
        } else {
            determinedSourceFolder = targetFileOrFolder
        }

        projectModel =
            ProjectModel(
                name = projectName,
                generatedFolder = genFolder.path,
                projectType = projectType,
                sourceFilePath = determinedSourceFolder.path,
                sourceDescriptor = sourceDescriptor
            )

        projectModels[projectInfoFile.path] = projectModel
        projectPaths.add(projectInfoFile.absolutePath)
        projectModelToPath[projectModel] = projectInfoFile.absolutePath
        currentProject = projectModel
        return projectModel
    }

    /**
     * loads the project.
     * Currently does nothing.
     * @return the project model
     * @param projectModel the model to load.
     */
    fun openProject(projectModel: ProjectModel): ProjectModel {
        currentProject = projectModel
        return projectModel
    }

    /**
     * Opens path and try loading, or loads from map when it already exists.
     * @param path path to the json file.
     * @throws NotProjectException when the file pointed by the path is not a valid project model file.
     */
    fun openProject(path: String): ProjectModel {
        var projectModel = projectModels[path]
        if (projectModel == null) {
            val jsonFile = File(path)
            try {
                val jsonString = jsonFile.inputStream().bufferedReader().use { it.readText() }
                projectModel =
                    Json.decodeFromString<ProjectModel>(ProjectModel.serializer(), jsonString)
            } catch (e: Exception) {
                when (e) {
                    is SerializationException,
                    is JSONException,
                    is IOException -> {
                        throw NotProjectException(path)
                    }
                }
            }
            projectModels[path] = projectModel
            projectPaths.add(path)
        }
        return openProject(projectModel)
    }

    /**
     * @param projectModel must be once registered.
     * @throws IllegalArgumentException if the path for the model does not exist.
     * Should call <code> newProject </code> or <code>openProject</code> first
     */
    fun save(projectModel: ProjectModel) {
        require(projectModelToPath.contains(projectModel))
        val jsonString = Json.encodeToString(projectModel)
        val file = File(requireNotNull(projectModelToPath[projectModel]))
        file.outputStream().bufferedWriter().use { it.write(jsonString) }
    }

    /**
     * @param projectModel ProjectModel to export
     * @param outDir The target directory
     * @return true if success else false
     */
    fun export(projectModel: ProjectModel, outDir: File): Boolean {
        val outZipFile = outDir.resolve(buildProjectExportFileName(projectModel.name))
        return exportArchive(projectModel, outZipFile)
    }

    fun exportArchive(projectModel: ProjectModel, outZipFile: File): Boolean {
        require(projectModelToPath.contains(projectModel))
        save(projectModel)
        saveAsZip(
            outZipFile,
            Pair(projectModel.sourceFilePath, "sourceFilePath"),
            Pair(projectModel.generatedFolder, "baseFolder"),
            Pair(projectModelToPath[projectModel]!!, "project_info.json")
        )
        return true
    }

    /**
     * @throws NotProjectException if project_info.json not found
     * @return projectModel
     */
    fun import(source: File): ProjectModel {
        val dest = appCtx.cacheDir.resolve("project-extract")
        dest.deleteRecursively()
        extractZip(source, dest)
        val infoFile = dest.resolve("project_info.json")
        if (!infoFile.isAccessible())
            throw NotProjectException(source.absolutePath)
        val extractedProjectModel = openProject(infoFile.absolutePath)
        val projectDir = rootdir.resolve(extractedProjectModel.name.toValidFileName())
        projectDir.deleteRecursively()
        projectDir.mkdirs()
        dest.copyRecursively(projectDir)
        dest.deleteRecursively()
        val relocatedProjectModel = relocateImportedProjectModel(extractedProjectModel, projectDir)
        val finalInfoFile = importedProjectInfoFile(projectDir)
        projectModels.remove(infoFile.absolutePath)
        projectPaths.remove(infoFile.absolutePath)
        projectModelToPath.remove(extractedProjectModel)
        projectModels[finalInfoFile.absolutePath] = relocatedProjectModel
        projectPaths.add(finalInfoFile.absolutePath)
        projectModelToPath[relocatedProjectModel] = finalInfoFile.absolutePath
        currentProject = relocatedProjectModel
        save(relocatedProjectModel)
        return relocatedProjectModel
        //        FileUtils.moveDirectory(dest.resolve("baseFolder"), projectDir.resolve("baseFolder"))
        //        FileUtils.moveDirectory(dest.resolve("sourceFilePath"), projectDir.resolve())
    }

//    fun getGenerated(relPath: String): File {
//        requireNotNull(currentProject)
//        requireNotNull(projectModelToPath[currentProject!!])
//        return File(currentProject!!.generatedFolder).resolve(relPath)
//    }
//
//    fun getOriginal(relPath: String): File {
//        requireNotNull(currentProject)
//        return File(currentProject!!.sourceFilePath).resolve(relPath)
//    }

//    fun getRelPathFromOrig(path: String): String {
//        val rootPath = getOriginal("").absolutePath
//        val relPath: String
//        if (path.length > rootPath.length)
//            relPath = path.substring(rootPath.length + 2)
//        else
//            relPath = ""
//        return relPath
//    }

    fun getRelPath(path: String): String {
        requireNotNull(currentProject)
        return computeProjectRelativePath(currentProject!!, path)
    }

    fun getRelPathOrNull(path: String): String? {
        val project = currentProject ?: return null
        return computeProjectRelativePathOrNull(project, path)
            .also {
                if (it == null) {
                    Logger.e(TAG, "Failed to resolve project-relative path for $path")
                }
            }
    }

//    fun getRelPathFromGen(path: String): String {
//        val rootPath = getGenerated("").absolutePath
//        val relPath: String
//        if (path.length > rootPath.length)
//            relPath = path.substring(rootPath.length + 1)
//        else
//            relPath = ""
//        return relPath
//    }

    private fun substringWithoutSlash(a: String, b: String): String {
        val sub = a.substring(b.length)
        if (sub.isNotEmpty() && sub[0] == '/')
            return sub.substring(1)
        return sub
    }
}

sealed class ProjectOpenAction {
    data object PromptCopy : ProjectOpenAction()
    data class OpenExistingProject(val projectInfoFile: File) : ProjectOpenAction()
    data class ImportProjectArchive(val archiveFile: File) : ProjectOpenAction()
}

internal fun determineProjectOpenAction(targetFile: File, openAsProject: Boolean): ProjectOpenAction {
    if (!openAsProject) {
        return ProjectOpenAction.PromptCopy
    }
    projectInfoFileForDirectory(targetFile)?.let {
        return ProjectOpenAction.OpenExistingProject(it)
    }
    if (isProjectArchiveFile(targetFile)) {
        return ProjectOpenAction.ImportProjectArchive(targetFile)
    }
    return ProjectOpenAction.PromptCopy
}

internal fun projectInfoFileForDirectory(targetFile: File): File? {
    if (!targetFile.isDirectory) {
        return null
    }
    val projectInfoFile = targetFile.resolve("project_info.json")
    return projectInfoFile.takeIf { it.isFile }
}

fun isProjectArchiveFile(targetFile: File): Boolean {
    if (!targetFile.isFile || !targetFile.extension.equals("zip", ignoreCase = true)) {
        return false
    }
    return runCatching {
        ZipFile(targetFile).use { zipFile ->
            zipFile.getEntry("project_info.json") != null
        }
    }.getOrDefault(false)
}

internal fun importedProjectInfoFile(projectDir: File): File {
    return projectDir.resolve("project_info.json")
}

internal fun relocateImportedProjectModel(projectModel: ProjectModel, projectDir: File): ProjectModel {
    return projectModel.copy(
        generatedFolder = projectDir.resolve("baseFolder").path,
        sourceFilePath = projectDir.resolve("sourceFilePath").path
    )
}

fun computeProjectRelativePath(projectModel: ProjectModel, path: String): String {
    if (path == projectModel.sourceFilePath) {
        return ""
    }

    val rootFilePath = projectModel.rootFile.absolutePath
    val absPath = File(path).absolutePath
    if (absPath.startsWith(rootFilePath)) {
        val orig = File(rootFilePath).resolve("original").path
        if (absPath.startsWith(orig)) {
            return substringWithoutLeadingSlash(absPath, orig)
        }

        val generated = File(projectModel.generatedFolder).absolutePath
        if (absPath.startsWith(generated)) {
            return substringWithoutLeadingSlash(absPath, generated)
        }
    }

    val srcPath = projectModel.sourceFilePath
    if (absPath.startsWith(srcPath)) {
        return substringWithoutLeadingSlash(absPath, srcPath)
    }

    Logger.e("ProjectManager", "getRelPath called on $path")
    throw IllegalArgumentException(
        "Path $absPath is not inside project ${projectModel.rootFile.absolutePath}"
    )
}

fun computeProjectRelativePathOrNull(projectModel: ProjectModel, path: String): String? {
    return runCatching { computeProjectRelativePath(projectModel, path) }.getOrNull()
}

private fun substringWithoutLeadingSlash(path: String, prefix: String): String {
    val sub = path.substring(prefix.length)
    if (sub.isNotEmpty() && sub[0] == '/') {
        return sub.substring(1)
    }
    return sub
}
