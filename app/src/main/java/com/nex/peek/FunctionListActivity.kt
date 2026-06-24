package com.nex.peek

import android.content.Intent
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
        WindowCompat.setDecorFitsSystemWindows(window, false)
        super.onCreate(savedInstanceState)
        b = ActivityFunctionListBinding.inflate(layoutInflater)
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
        supportActionBar?.title = "Functions"

        adapter = FunctionAdapter { fn ->
            startActivity(Intent(this, DisassemblyActivity::class.java).apply {
                putExtra(DisassemblyActivity.EXTRA_FUNC_ID,      fn.id)
                putExtra(DisassemblyActivity.EXTRA_FUNC_ADDRESS, fn.address.toLong())
                putExtra(DisassemblyActivity.EXTRA_FUNC_NAME,    fn.displayName)
            })
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
            supportActionBar?.title = "Functions (${fns.size})"
        }
    }

    private fun filterFunctions(query: String) {
        adapter.submitList(
            if (query.isBlank()) allFunctions
            else allFunctions.filter { fn ->
                fn.displayName.contains(query, ignoreCase = true) ||
                fn.addressHex.contains(query, ignoreCase = true)
            }
        )
    }

    override fun onSupportNavigateUp(): Boolean { finish(); return true }
}
