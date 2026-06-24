package com.kyhsgeekcode.disassembler

import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class MainActivitySmokeTest {
    @Test
    fun launchMainActivity_reachesResumedState() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            assertEquals(Lifecycle.State.RESUMED, scenario.state)
        }
    }

    @Test
    fun recreateMainActivity_returnsToResumedState() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.recreate()

            assertEquals(Lifecycle.State.RESUMED, scenario.state)
        }
    }
}
