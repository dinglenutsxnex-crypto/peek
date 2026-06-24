package com.kyhsgeekcode.disassembler.project.models

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.io.File

@Serializable
enum class ProjectSourceKind {
    @SerialName("file-path")
    FILE_PATH,

    @SerialName("content-uri")
    CONTENT_URI,

    @SerialName("app-private-file")
    APP_PRIVATE_FILE,

    @SerialName("extracted-cache-file")
    EXTRACTED_CACHE_FILE
}

@Serializable
data class ProjectSourceDescriptor(
    @SerialName("kind")
    val kind: ProjectSourceKind,
    @SerialName("location")
    val location: String
)

fun legacyProjectSourceDescriptor(sourceFilePath: String): ProjectSourceDescriptor {
    return ProjectSourceDescriptor(ProjectSourceKind.FILE_PATH, sourceFilePath)
}

@Serializable
data class ProjectModel(
    @SerialName("projectName")
    var name: String = "New project",
    /**
     * The folder for temp analysis files
     */
    @SerialName("generated")
    var generatedFolder: String,
    @SerialName("projectType")
    var projectType: String,
    /**
     * The file/folder user chose to open
     */
    @SerialName("sourceFilePath")
    var sourceFilePath: String,
    @SerialName("sourceDescriptor")
    var sourceDescriptor: ProjectSourceDescriptor? = null,
    @SerialName("info")
    val info: ArrayList<ProjectFileModel> = ArrayList()
) {
    val rootFile: File
        get() = requireNotNull(File(generatedFolder).parentFile)

    val sourceFile: File
        get() = File(sourceFilePath)

    val sourceLibrariesDirectory: File
        get() = File("${sourceFile.absolutePath}_libs")

    val resolvedSourceDescriptor: ProjectSourceDescriptor
        get() = sourceDescriptor ?: legacyProjectSourceDescriptor(sourceFilePath)
}
