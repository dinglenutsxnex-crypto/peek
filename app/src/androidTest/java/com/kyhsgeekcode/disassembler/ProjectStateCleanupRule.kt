package com.kyhsgeekcode.disassembler

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.kyhsgeekcode.disassembler.project.ProjectManager
import org.junit.rules.ExternalResource

class ProjectStateCleanupRule : ExternalResource() {
    override fun before() {
        clearState()
    }

    override fun after() {
        clearState()
    }

    private fun clearState() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        ProjectManager.currentProject = null
        ProjectManager.projectModels.clear()
        ProjectManager.projectModelToPath.clear()
        ProjectManager.projectPaths.clear()
        context.getSharedPreferences("ProjectManager", Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()
        context.getSharedPreferences(MainActivity.SETTINGKEY, Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()
        context.filesDir.resolve("imports").deleteRecursively()
        context.cacheDir.resolve("exports").deleteRecursively()
        ProjectManager.rootdir.deleteRecursively()
        ProjectManager.rootdir.mkdirs()
    }
}
