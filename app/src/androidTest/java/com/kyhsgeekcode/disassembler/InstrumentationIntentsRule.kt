package com.kyhsgeekcode.disassembler

import androidx.test.espresso.intent.Intents
import org.junit.rules.ExternalResource

class InstrumentationIntentsRule : ExternalResource() {
    override fun before() {
        Intents.init()
    }

    override fun after() {
        Intents.release()
    }
}
