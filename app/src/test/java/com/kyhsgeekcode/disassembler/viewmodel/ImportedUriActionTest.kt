package com.kyhsgeekcode.disassembler.viewmodel

import com.kyhsgeekcode.disassembler.project.models.ProjectSourceKind
import java.io.File
import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class ImportedUriActionTest {
    @Test
    fun `determineImportedUriAction imports project archive when copied file is project zip`() {
        val archive = createProjectArchive(createTempDirectory("imported-uri"))

        val action = determineImportedUriAction(
            importedFile = archive,
            sourceUriLocation = "content://test/project.zip"
        )

        val importArchive = assertIs<ImportedUriAction.ImportProjectArchive>(action)
        assertEquals(archive, importArchive.archiveFile)
    }

    @Test
    fun `determineImportedUriAction creates project with content uri descriptor for regular file`() {
        val file = createTempDirectory("imported-uri").toFile().resolve("sample.apk").apply {
            writeText("apk")
        }

        val action = determineImportedUriAction(
            importedFile = file,
            sourceUriLocation = "content://test/sample.apk"
        )

        val createProject = assertIs<ImportedUriAction.CreateProject>(action)
        assertEquals(file, createProject.importedFile)
        assertEquals(ProjectSourceKind.CONTENT_URI, createProject.sourceDescriptor.kind)
        assertEquals("content://test/sample.apk", createProject.sourceDescriptor.location)
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
