package com.kyhsgeekcode.disassembler.viewmodel

import com.kyhsgeekcode.disassembler.project.ProjectOpenAction
import com.kyhsgeekcode.disassembler.project.determineProjectOpenAction
import java.io.File
import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class ProjectOpenActionTest {
    @Test
    fun `determineProjectOpenAction prompts copy when openAsProject is false`() {
        val file = createTempDirectory("project-open").toFile().resolve("sample.apk").apply {
            writeText("apk")
        }

        val action = determineProjectOpenAction(file, openAsProject = false)

        assertIs<ProjectOpenAction.PromptCopy>(action)
    }

    @Test
    fun `determineProjectOpenAction opens existing project directory`() {
        val projectDir = createTempDirectory("project-open").toFile().apply {
            resolve("project_info.json").writeText("{}")
        }

        val action = determineProjectOpenAction(projectDir, openAsProject = true)

        val openExisting = assertIs<ProjectOpenAction.OpenExistingProject>(action)
        assertEquals(projectDir.resolve("project_info.json"), openExisting.projectInfoFile)
    }

    @Test
    fun `determineProjectOpenAction imports project archive`() {
        val archive = createProjectArchive(createTempDirectory("project-open"))

        val action = determineProjectOpenAction(archive, openAsProject = true)

        val importArchive = assertIs<ProjectOpenAction.ImportProjectArchive>(action)
        assertEquals(archive, importArchive.archiveFile)
    }

    @Test
    fun `determineProjectOpenAction falls back to copy prompt for non project directory`() {
        val folder = createTempDirectory("project-open").toFile()

        val action = determineProjectOpenAction(folder, openAsProject = true)

        assertIs<ProjectOpenAction.PromptCopy>(action)
    }

    @Test
    fun `determineProjectOpenAction falls back to copy prompt for non project archive`() {
        val archive = createTempDirectory("project-open").toFile().resolve("plain.zip").apply {
            ZipOutputStream(outputStream()).use { zip ->
                zip.putNextEntry(ZipEntry("classes.dex"))
                zip.write("dex".encodeToByteArray())
                zip.closeEntry()
            }
        }

        val action = determineProjectOpenAction(archive, openAsProject = true)

        assertIs<ProjectOpenAction.PromptCopy>(action)
    }

    private fun createProjectArchive(tempDir: Path): File {
        return tempDir.toFile().resolve("project.zip").apply {
            ZipOutputStream(outputStream()).use { zip ->
                zip.putNextEntry(ZipEntry("project_info.json"))
                zip.write("{}".encodeToByteArray())
                zip.closeEntry()
                zip.putNextEntry(ZipEntry("sourceFilePath"))
                zip.write("sample".encodeToByteArray())
                zip.closeEntry()
            }
        }
    }
}
