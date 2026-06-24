package com.kyhsgeekcode.disassembler

import com.kyhsgeekcode.disassembler.project.computeProjectRelativePath
import com.kyhsgeekcode.disassembler.project.computeProjectRelativePathOrNull
import com.kyhsgeekcode.disassembler.project.importedProjectInfoFile
import com.kyhsgeekcode.disassembler.project.relocateImportedProjectModel
import com.kyhsgeekcode.disassembler.project.models.ProjectSourceDescriptor
import com.kyhsgeekcode.disassembler.project.models.ProjectSourceKind
import com.kyhsgeekcode.disassembler.project.models.ProjectModel
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.io.File

class ProjectManagerTest {
    @Test
    fun `computeProjectRelativePath returns empty string for project source root`() {
        val project = projectModelFor("sample")

        val relPath = computeProjectRelativePath(project, "sample")

        assertEquals("", relPath)
    }

    @Test
    fun `computeProjectRelativePath strips original directory prefix`() {
        val project = projectModelFor("sample")
        val originalChild = projectRoot()
            .resolve("original")
            .resolve("sample")
            .resolve("classes.dex")

        val relPath = computeProjectRelativePath(project, originalChild.path)

        assertEquals("sample/classes.dex", relPath)
    }

    @Test
    fun `computeProjectRelativePath strips generated directory prefix`() {
        val project = projectModelFor("sample")
        val generatedChild = projectRoot()
            .resolve("generated")
            .resolve("sample")
            .resolve("classes.dex.txt")

        val relPath = computeProjectRelativePath(project, generatedChild.path)

        assertEquals("sample/classes.dex.txt", relPath)
    }

    @Test
    fun `computeProjectRelativePath throws for paths outside project boundaries`() {
        val project = projectModelFor("sample")

        assertThrows(IllegalArgumentException::class.java) {
            computeProjectRelativePath(project, "outside-project/classes.dex")
        }
    }

    @Test
    fun `computeProjectRelativePathOrNull returns null for paths outside project boundaries`() {
        val project = projectModelFor("sample")

        assertEquals(null, computeProjectRelativePathOrNull(project, "outside-project/classes.dex"))
    }

    @Test
    fun `resolvedSourceDescriptor falls back to legacy file path`() {
        val project = projectModelFor("sample")

        assertEquals(ProjectSourceKind.FILE_PATH, project.resolvedSourceDescriptor.kind)
        assertEquals("sample", project.resolvedSourceDescriptor.location)
    }

    @Test
    fun `resolvedSourceDescriptor prefers explicit descriptor`() {
        val project = projectModelFor(
            sourceName = "sample",
            sourceDescriptor = ProjectSourceDescriptor(
                ProjectSourceKind.CONTENT_URI,
                "content://samples/app.apk"
            )
        )

        assertEquals(ProjectSourceKind.CONTENT_URI, project.resolvedSourceDescriptor.kind)
        assertEquals("content://samples/app.apk", project.resolvedSourceDescriptor.location)
    }

    @Test
    fun `sourceFile exposes sourceFilePath as File`() {
        val project = projectModelFor("sample.apk")

        assertEquals(File("sample.apk"), project.sourceFile)
    }

    @Test
    fun `sourceLibrariesDirectory appends libs suffix next to source file`() {
        val project = projectModelFor("sample.apk")

        assertEquals(
            File("${project.sourceFile.absolutePath}_libs"),
            project.sourceLibrariesDirectory
        )
    }

    @Test
    fun `relocateImportedProjectModel rewrites source and generated paths into project dir`() {
        val project = projectModelFor(
            sourceName = "temp/sourceFilePath",
            sourceDescriptor = ProjectSourceDescriptor(
                ProjectSourceKind.CONTENT_URI,
                "content://samples/app.apk"
            )
        ).copy(generatedFolder = "temp/baseFolder")
        val projectDir = File("imported-project")

        val relocated = relocateImportedProjectModel(project, projectDir)

        assertEquals(projectDir.resolve("sourceFilePath").path, relocated.sourceFilePath)
        assertEquals(projectDir.resolve("baseFolder").path, relocated.generatedFolder)
        assertEquals(project.sourceDescriptor, relocated.sourceDescriptor)
    }

    @Test
    fun `importedProjectInfoFile resolves inside project dir`() {
        val projectDir = File("imported-project")

        assertEquals(
            projectDir.resolve("project_info.json"),
            importedProjectInfoFile(projectDir)
        )
    }

    private fun projectModelFor(
        sourceName: String,
        sourceDescriptor: ProjectSourceDescriptor? = null
    ): ProjectModel {
        return ProjectModel(
            name = "Sample",
            generatedFolder = projectRoot().resolve("generated").path,
            projectType = "UNKNOWN",
            sourceFilePath = sourceName,
            sourceDescriptor = sourceDescriptor
        )
    }

    private fun projectRoot(): File = File("project-root")
}
