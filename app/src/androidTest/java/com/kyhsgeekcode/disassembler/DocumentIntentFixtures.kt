package com.kyhsgeekcode.disassembler

import android.app.Activity
import android.app.Instrumentation
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.FileProvider
import androidx.test.core.app.ApplicationProvider
import com.kyhsgeekcode.disassembler.project.models.ProjectModel
import com.kyhsgeekcode.disassembler.project.models.ProjectSourceDescriptor
import com.kyhsgeekcode.disassembler.project.models.ProjectSourceKind
import com.kyhsgeekcode.disassembler.project.models.ProjectType
import com.kyhsgeekcode.filechooser.NewFileChooserActivity
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

private const val FILE_PROVIDER_AUTHORITY = "com.kyhsgeekcode.disassembler.provider"

fun createIncomingContentUri(
    displayName: String,
    content: ByteArray
): Uri {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val inputFile = context.filesDir.resolve("androidTest/input/$displayName")
    inputFile.parentFile?.mkdirs()
    inputFile.writeBytes(content)
    return testFileUri(context, inputFile)
}

fun createActionViewIntent(
    displayName: String,
    content: ByteArray
): Intent {
    val uri = createIncomingContentUri(displayName, content)
    return Intent(
        ApplicationProvider.getApplicationContext(),
        MainActivity::class.java
    ).apply {
        action = Intent.ACTION_VIEW
        data = uri
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        addFlags(Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)
    }
}

fun createExtraStreamIntent(
    displayName: String,
    content: ByteArray
): Intent {
    val uri = createIncomingContentUri(displayName, content)
    return Intent(
        ApplicationProvider.getApplicationContext(),
        MainActivity::class.java
    ).apply {
        action = Intent.ACTION_SEND
        type = "*/*"
        putExtra(Intent.EXTRA_STREAM, uri)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        addFlags(Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)
    }
}

fun createOpenDocumentResult(
    displayName: String,
    content: ByteArray
): Instrumentation.ActivityResult {
    val uri = createIncomingContentUri(displayName, content)
    val resultIntent = Intent()
        .setData(uri)
        .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        .addFlags(Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)
    return Instrumentation.ActivityResult(Activity.RESULT_OK, resultIntent)
}

fun createCreateDocumentResult(
    displayName: String
): Pair<File, Instrumentation.ActivityResult> {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val outputFile = context.cacheDir.resolve("androidTest/output/$displayName")
    outputFile.parentFile?.mkdirs()
    outputFile.writeBytes(byteArrayOf())
    val uri = testFileUri(context, outputFile)
    val resultIntent = Intent()
        .setData(uri)
        .addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
        .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    return outputFile to Instrumentation.ActivityResult(Activity.RESULT_OK, resultIntent)
}

fun createCanceledActivityResult(): Instrumentation.ActivityResult {
    return Instrumentation.ActivityResult(Activity.RESULT_CANCELED, null)
}

fun createAdvancedImportResultForFile(
    file: File,
    openProject: Boolean = false,
    projectType: String = ProjectType.UNKNOWN
): Instrumentation.ActivityResult {
    val resultIntent = Intent().apply {
        putExtra(NewFileChooserActivity.EXTRA_FILE_PATH, file.absolutePath)
        putExtra(NewFileChooserActivity.EXTRA_PROJECT_TYPE, projectType)
        putExtra("openProject", openProject)
    }
    return Instrumentation.ActivityResult(Activity.RESULT_OK, resultIntent)
}

fun createProjectArchiveFixture(): File {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val archiveFile = context.cacheDir.resolve("androidTest/archive-fixture/ArchiveFixture.zip")
    archiveFile.parentFile?.mkdirs()
    val projectModel = ProjectModel(
        name = "ArchiveFixture",
        generatedFolder = "baseFolder",
        projectType = ProjectType.UNKNOWN,
        sourceFilePath = "sourceFilePath",
        sourceDescriptor = ProjectSourceDescriptor(
            ProjectSourceKind.APP_PRIVATE_FILE,
            "imports/ArchiveFixture.bin"
        )
    )
    ZipOutputStream(archiveFile.outputStream()).use { zip ->
        zip.putNextEntry(ZipEntry("project_info.json"))
        zip.write(Json.encodeToString(projectModel).encodeToByteArray())
        zip.closeEntry()

        zip.putNextEntry(ZipEntry("sourceFilePath"))
        zip.write("fixture-binary".encodeToByteArray())
        zip.closeEntry()

        zip.putNextEntry(ZipEntry("baseFolder/"))
        zip.closeEntry()
    }

    return archiveFile
}

private fun testFileUri(context: Context, file: File): Uri {
    return FileProvider.getUriForFile(context, FILE_PROVIDER_AUTHORITY, file)
}
