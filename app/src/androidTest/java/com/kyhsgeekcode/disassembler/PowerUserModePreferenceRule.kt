package com.kyhsgeekcode.disassembler

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.kyhsgeekcode.disassembler.preference.PowerUserModeSettings
import org.junit.rules.ExternalResource

class PowerUserModePreferenceRule(
    private val powerUserModeEnabled: Boolean
) : ExternalResource() {
    override fun before() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        context.getSharedPreferences(MainActivity.SETTINGKEY, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(
                PowerUserModeSettings.POWER_USER_IMPORT_MODE_KEY,
                powerUserModeEnabled
            )
            .apply()
    }

    override fun after() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        context.getSharedPreferences(MainActivity.SETTINGKEY, Context.MODE_PRIVATE)
            .edit()
            .remove(PowerUserModeSettings.POWER_USER_IMPORT_MODE_KEY)
            .apply()
    }
}
