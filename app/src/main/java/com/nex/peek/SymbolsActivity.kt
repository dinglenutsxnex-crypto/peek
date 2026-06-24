package com.nex.peek

import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.MenuItem
import androidx.appcompat.app.AppCompatActivity
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
        super.onCreate(savedInstanceState)
        b = ActivitySymbolsBinding.inflate(layoutInflater)
        setContentView(b.root)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        title = "Symbols"

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
            title = "Symbols (${syms.size})"
        }
    }

    private fun filterSymbols(query: String) {
        val filtered = if (query.isBlank()) {
            allSymbols
        } else {
            allSymbols.filter { s ->
                s.name.contains(query, ignoreCase = true) ||
                s.addressHex.contains(query, ignoreCase = true)
            }
        }
        adapter.submitList(filtered)
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) { finish(); return true }
        return super.onOptionsItemSelected(item)
    }
}
