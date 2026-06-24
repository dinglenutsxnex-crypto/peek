package com.kyhsgeekcode.disassembler.preference

import android.content.Context
import com.kyhsgeekcode.disassembler.MainActivity
import com.kyhsgeekcode.disassembler.importing.AdvancedImportOptions

object PowerUserModeSettings {
    const val POWER_USER_IMPORT_MODE_KEY = "power_user_import_mode"
    const val POWER_USER_FILESYSTEM_IMPORT_KEY = "power_user_filesystem_import"
    const val POWER_USER_APPS_IMPORT_KEY = "power_user_apps_import"
    const val POWER_USER_RESEARCH_TOOLS_IMPORT_KEY = "power_user_research_tools_import"

    fun isEnabled(context: Context): Boolean {
        return context.getSharedPreferences(MainActivity.SETTINGKEY, Context.MODE_PRIVATE)
            .getBoolean(POWER_USER_IMPORT_MODE_KEY, false)
    }

    fun advancedImportOptions(context: Context): AdvancedImportOptions {
        val prefs = context.getSharedPreferences(MainActivity.SETTINGKEY, Context.MODE_PRIVATE)
        return AdvancedImportOptions(
            powerUserMode = prefs.getBoolean(POWER_USER_IMPORT_MODE_KEY, false),
            filesystemAccess = prefs.getBoolean(POWER_USER_FILESYSTEM_IMPORT_KEY, true),
            installedAppsAccess = prefs.getBoolean(POWER_USER_APPS_IMPORT_KEY, true),
            researchToolsAccess = prefs.getBoolean(POWER_USER_RESEARCH_TOOLS_IMPORT_KEY, false)
        )
    }
}
