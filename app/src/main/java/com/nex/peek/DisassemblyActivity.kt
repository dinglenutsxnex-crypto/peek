package com.nex.peek

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import androidx.core.view.updatePadding
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.nex.peek.adapter.InstructionAdapter
import com.nex.peek.databinding.ActivityDisassemblyBinding
import com.nex.peek.model.InstructionInfo
import com.nex.peek.ui.AnalysisSession
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class DisassemblyActivity : AppCompatActivity() {

    private lateinit var b: ActivityDisassemblyBinding
    private lateinit var adapter: InstructionAdapter

    private var funcId: Long      = 0L
    private var funcAddress: Long = 0L
    private var totalCount: Long  = 0L
    private var currentOffset: Int = 0
    private var isLoading: Boolean = false

    private val PAGE = 200

    override fun onCreate(savedInstanceState: Bundle?) {
        WindowCompat.setDecorFitsSystemWindows(window, false)
        super.onCreate(savedInstanceState)
        b = ActivityDisassemblyBinding.inflate(layoutInflater)
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

        funcId      = intent.getLongExtra(EXTRA_FUNC_ID, 0L)
        funcAddress = intent.getLongExtra(EXTRA_FUNC_ADDRESS, 0L)
        val name    = intent.getStringExtra(EXTRA_FUNC_NAME) ?: "Unknown"
        supportActionBar?.title = name

        adapter = InstructionAdapter { insn -> openXrefs(insn) }
        b.recyclerView.layoutManager = LinearLayoutManager(this)
        b.recyclerView.adapter = adapter

        b.btnXrefs.setOnClickListener {
            startActivity(Intent(this, XrefActivity::class.java).apply {
                putExtra(XrefActivity.EXTRA_ADDRESS, funcAddress)
                putExtra(XrefActivity.EXTRA_LABEL,   name)
            })
        }

        b.recyclerView.addOnScrollListener(object : RecyclerView.OnScrollListener() {
            override fun onScrolled(rv: RecyclerView, dx: Int, dy: Int) {
                if (dy <= 0 || isLoading) return
                val lm = rv.layoutManager as LinearLayoutManager
                if (lm.findLastVisibleItemPosition() >= adapter.itemCount - 20 &&
                    currentOffset < totalCount) loadPage()
            }
        })

        lifecycleScope.launch {
            totalCount = withContext(Dispatchers.IO) {
                PeekNative.getInstructionCount(AnalysisSession.get(), funcId)
            }
            b.tvCount.text = "$totalCount instructions"
            loadPage()
        }
    }

    private fun loadPage() {
        if (isLoading || currentOffset >= totalCount) return
        isLoading = true
        b.progressBar.visibility = View.VISIBLE
        lifecycleScope.launch {
            val page = withContext(Dispatchers.IO) {
                PeekNative.getInstructions(AnalysisSession.get(), funcId, PAGE, currentOffset)
            }
            val existing = (0 until adapter.itemCount).map { adapter.currentList[it] }
            adapter.submitList(existing + page)
            currentOffset += page.size
            isLoading = false
            b.progressBar.visibility = View.GONE
        }
    }

    private fun openXrefs(insn: InstructionInfo) {
        startActivity(Intent(this, XrefActivity::class.java).apply {
            putExtra(XrefActivity.EXTRA_ADDRESS, insn.address.toLong())
            putExtra(XrefActivity.EXTRA_LABEL,   insn.addressHex)
        })
    }

    override fun onSupportNavigateUp(): Boolean { finish(); return true }

    companion object {
        const val EXTRA_FUNC_ID      = "func_id"
        const val EXTRA_FUNC_ADDRESS = "func_address"
        const val EXTRA_FUNC_NAME    = "func_name"
    }
}
