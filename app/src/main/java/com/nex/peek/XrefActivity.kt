package com.nex.peek

import android.os.Build
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import androidx.core.view.updatePadding
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.nex.peek.adapter.XrefAdapter
import com.nex.peek.databinding.ActivityXrefBinding
import com.nex.peek.ui.AnalysisSession
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class XrefActivity : AppCompatActivity() {

    private lateinit var b: ActivityXrefBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        WindowCompat.setDecorFitsSystemWindows(window, false)
        super.onCreate(savedInstanceState)
        b = ActivityXrefBinding.inflate(layoutInflater)
        setContentView(b.root)

        WindowInsetsControllerCompat(window, window.decorView).apply {
            hide(WindowInsetsCompat.Type.navigationBars())
            systemBarsBehavior =
                WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            window.isNavigationBarContrastEnforced = false
        }

        ViewCompat.setOnApplyWindowInsetsListener(b.rootLayout) { _, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            b.toolbar.updatePadding(top = bars.top)
            insets
        }

        setSupportActionBar(b.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)

        val address = intent.getLongExtra(EXTRA_ADDRESS, 0L).toULong()
        val label   = intent.getStringExtra(EXTRA_LABEL) ?: "0x${address.toString(16)}"
        supportActionBar?.title = "XRefs: $label"

        val adapter = XrefAdapter(address)
        b.recyclerView.layoutManager = LinearLayoutManager(this)
        b.recyclerView.adapter = adapter

        lifecycleScope.launch {
            val xrefs = withContext(Dispatchers.IO) {
                PeekNative.getXrefs(AnalysisSession.get(), address)
            }
            adapter.submitList(xrefs)
            b.tvCount.text = "${xrefs.size} cross-references"
        }
    }

    override fun onSupportNavigateUp(): Boolean { finish(); return true }

    companion object {
        const val EXTRA_ADDRESS = "address"
        const val EXTRA_LABEL   = "label"
    }
}
