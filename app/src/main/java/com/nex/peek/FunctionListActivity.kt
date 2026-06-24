package com.nex.peek

import android.content.Intent
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.MenuItem
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.nex.peek.adapter.FunctionAdapter
import com.nex.peek.databinding.ActivityFunctionListBinding
import com.nex.peek.model.FunctionInfo
import com.nex.peek.ui.AnalysisSession
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class FunctionListActivity : AppCompatActivity() {

    private lateinit var b: ActivityFunctionListBinding
    private lateinit var adapter: FunctionAdapter
    private var allFunctions: List<FunctionInfo> = emptyList()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        b = ActivityFunctionListBinding.inflate(layoutInflater)
        setContentView(b.root)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        title = "Functions"

        adapter = FunctionAdapter { fn ->
            val intent = Intent(this, DisassemblyActivity::class.java).apply {
                putExtra(DisassemblyActivity.EXTRA_FUNC_ID,      fn.id)
                putExtra(DisassemblyActivity.EXTRA_FUNC_ADDRESS, fn.address.toLong())
                putExtra(DisassemblyActivity.EXTRA_FUNC_NAME,    fn.displayName)
            }
            startActivity(intent)
        }

        b.recyclerView.layoutManager = LinearLayoutManager(this)
        b.recyclerView.adapter = adapter

        b.etSearch.addTextChangedListener(object : TextWatcher {
            override fun afterTextChanged(s: Editable?) = filterFunctions(s?.toString() ?: "")
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
        })

        b.btnSymbols.setOnClickListener {
            startActivity(Intent(this, SymbolsActivity::class.java))
        }

        loadFunctions()
    }

    private fun loadFunctions() {
        lifecycleScope.launch {
            val fns = withContext(Dispatchers.IO) {
                PeekNative.getFunctionList(AnalysisSession.get())
            }
            allFunctions = fns
            adapter.submitList(fns)
            title = "Functions (${fns.size})"
        }
    }

    private fun filterFunctions(query: String) {
        val filtered = if (query.isBlank()) {
            allFunctions
        } else {
            allFunctions.filter { fn ->
                fn.displayName.contains(query, ignoreCase = true) ||
                fn.addressHex.contains(query, ignoreCase = true)
            }
        }
        adapter.submitList(filtered)
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) { finish(); return true }
        return super.onOptionsItemSelected(item)
    }
}
