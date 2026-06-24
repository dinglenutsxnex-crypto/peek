package com.nex.peek

import android.os.Bundle
import android.view.MenuItem
import androidx.appcompat.app.AppCompatActivity
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
        super.onCreate(savedInstanceState)
        b = ActivityXrefBinding.inflate(layoutInflater)
        setContentView(b.root)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)

        val address = intent.getLongExtra(EXTRA_ADDRESS, 0L).toULong()
        val label   = intent.getStringExtra(EXTRA_LABEL) ?: "0x${address.toString(16)}"
        title = "XRefs: $label"

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

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) { finish(); return true }
        return super.onOptionsItemSelected(item)
    }

    companion object {
        const val EXTRA_ADDRESS = "address"
        const val EXTRA_LABEL   = "label"
    }
}
