package com.nex.peek

import android.os.Build
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import androidx.core.view.updatePadding
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.nex.peek.adapter.SymbolAdapter
import com.nex.peek.databinding.ActivitySymbolsBinding
import com.nex.peek.model.SymbolInfo
import com.nex.peek.ui.AnalysisSession
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class SymbolsActivity : AppCompatActivity() {

    private lateinit var b: ActivitySymbolsBinding
    private lateinit var adapter: SymbolAdapter
    private var allSymbols: List<SymbolInfo> = emptyList()

    override fun onCreate(savedInstanceState: Bundle?) {
        WindowCompat.setDecorFitsSystemWindows(window, false)
        super.onCreate(savedInstanceState)
        b = ActivitySymbolsBinding.inflate(layoutInflater)
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
        supportActionBar?.title = "Symbols"

        adapter = SymbolAdapter()
        b.recyclerView.layoutManager = LinearLayoutManager(this)
        b.recyclerView.adapter = adapter

        b.etSearch.addTextChangedListener(object : TextWatcher {
            override fun afterTextChanged(s: Editable?) = filterSymbols(s?.toString() ?: "")
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
        })

        lifecycleScope.launch {
            val syms = withContext(Dispatchers.IO) {
                PeekNative.getSymbols(AnalysisSession.get())
            }
            allSymbols = syms
            adapter.submitList(syms)
            supportActionBar?.title = "Symbols (${syms.size})"
        }
    }

    private fun filterSymbols(query: String) {
        adapter.submitList(
            if (query.isBlank()) allSymbols
            else allSymbols.filter { s ->
                s.name.contains(query, ignoreCase = true) ||
                s.addressHex.contains(query, ignoreCase = true)
            }
        )
    }

    override fun onSupportNavigateUp(): Boolean { finish(); return true }
}
