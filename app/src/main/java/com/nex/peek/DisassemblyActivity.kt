package com.nex.peek

import android.content.Intent
import android.os.Bundle
import android.view.MenuItem
import android.view.View
import androidx.appcompat.app.AppCompatActivity
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
        super.onCreate(savedInstanceState)
        b = ActivityDisassemblyBinding.inflate(layoutInflater)
        setContentView(b.root)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)

        funcId      = intent.getLongExtra(EXTRA_FUNC_ID, 0L)
        funcAddress = intent.getLongExtra(EXTRA_FUNC_ADDRESS, 0L)
        val name    = intent.getStringExtra(EXTRA_FUNC_NAME) ?: "Unknown"
        title = name

        adapter = InstructionAdapter { insn ->
            openXrefs(insn)
        }

        b.recyclerView.layoutManager = LinearLayoutManager(this)
        b.recyclerView.adapter = adapter

        b.btnXrefs.setOnClickListener {
            val intent = Intent(this, XrefActivity::class.java).apply {
                putExtra(XrefActivity.EXTRA_ADDRESS, funcAddress)
                putExtra(XrefActivity.EXTRA_LABEL,   name)
            }
            startActivity(intent)
        }

        b.recyclerView.addOnScrollListener(object : RecyclerView.OnScrollListener() {
            override fun onScrolled(rv: RecyclerView, dx: Int, dy: Int) {
                if (dy <= 0 || isLoading) return
                val lm = rv.layoutManager as LinearLayoutManager
                val last = lm.findLastVisibleItemPosition()
                if (last >= adapter.itemCount - 20 && currentOffset < totalCount) {
                    loadPage()
                }
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
            val combined = existing + page
            adapter.submitList(combined)
            currentOffset += page.size
            isLoading = false
            b.progressBar.visibility = View.GONE
        }
    }

    private fun openXrefs(insn: InstructionInfo) {
        val intent = Intent(this, XrefActivity::class.java).apply {
            putExtra(XrefActivity.EXTRA_ADDRESS, insn.address.toLong())
            putExtra(XrefActivity.EXTRA_LABEL,   insn.addressHex)
        }
        startActivity(intent)
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) { finish(); return true }
        return super.onOptionsItemSelected(item)
    }

    companion object {
        const val EXTRA_FUNC_ID      = "func_id"
        const val EXTRA_FUNC_ADDRESS = "func_address"
        const val EXTRA_FUNC_NAME    = "func_name"
    }
}
