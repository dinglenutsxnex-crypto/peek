package com.nex.peek.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.res.ColorStateList
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.nex.peek.PeekNative
import com.nex.peek.R
import com.nex.peek.XrefActivity
import com.nex.peek.adapter.InstructionAdapter
import com.nex.peek.databinding.FragmentDisassemblyBinding
import com.nex.peek.model.FunctionInfo
import com.nex.peek.model.InstructionInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class DisassemblyFragment : Fragment() {

    private var _b: FragmentDisassemblyBinding? = null
    private val b get() = _b!!

    private val vm: AnalysisViewModel by activityViewModels()
    private lateinit var insAdapter: InstructionAdapter

    private val buffer = mutableListOf<InstructionInfo>()
    private var currentFunc: FunctionInfo? = null
    private var loadedCount = 0
    private var totalCount = 0L
    private var loading = false

    companion object {
        private const val PAGE = 200
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _b = FragmentDisassemblyBinding.inflate(inflater, container, false)
        return b.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        insAdapter = InstructionAdapter()
        b.rvInstructions.layoutManager = LinearLayoutManager(requireContext())
        b.rvInstructions.adapter = insAdapter

        b.rvInstructions.addOnScrollListener(object : RecyclerView.OnScrollListener() {
            override fun onScrolled(rv: RecyclerView, dx: Int, dy: Int) {
                if (!loading && loadedCount < totalCount) {
                    val lm = rv.layoutManager as LinearLayoutManager
                    if (lm.findLastVisibleItemPosition() >= insAdapter.itemCount - 40) {
                        loadNextPage()
                    }
                }
            }
        })

        b.fabXrefs.setOnClickListener {
            val fn = currentFunc ?: return@setOnClickListener
            startActivity(Intent(requireContext(), XrefActivity::class.java).apply {
                putExtra(XrefActivity.EXTRA_ADDRESS, fn.address.toLong())
                putExtra(XrefActivity.EXTRA_LABEL, fn.displayName)
            })
        }

        b.btnCopy.setOnClickListener { copyToClipboard() }

        vm.selectedFunction.observe(viewLifecycleOwner) { fn ->
            if (fn != null) loadFunction(fn)
        }
    }

    private fun loadFunction(fn: FunctionInfo) {
        currentFunc = fn
        loadedCount = 0
        totalCount = 0L
        loading = false
        buffer.clear()
        insAdapter.submitList(emptyList())
        b.tvEmpty.visibility = View.GONE
        b.fabXrefs.visibility = View.GONE
        b.btnCopy.visibility = View.GONE
        b.progressBar.visibility = View.VISIBLE

        lifecycleScope.launch {
            val handle = AnalysisSession.get()
            val count = withContext(Dispatchers.IO) {
                PeekNative.getInstructionCount(handle, fn.id)
            }
            totalCount = count
            if (count == 0L) {
                b.progressBar.visibility = View.GONE
                b.tvEmpty.text = "No instructions"
                b.tvEmpty.visibility = View.VISIBLE
            } else {
                loadNextPage()
            }
        }
    }

    private fun loadNextPage() {
        val fn = currentFunc ?: return
        if (loading) return
        loading = true

        lifecycleScope.launch {
            val handle = AnalysisSession.get()
            val page = withContext(Dispatchers.IO) {
                PeekNative.getInstructions(handle, fn.id, PAGE, loadedCount)
            }
            buffer.addAll(page)
            loadedCount += page.size
            insAdapter.submitList(buffer.toList())
            b.progressBar.visibility = View.GONE
            if (buffer.isNotEmpty()) {
                b.fabXrefs.visibility = View.VISIBLE
                b.btnCopy.visibility = View.VISIBLE
            }
            loading = false
        }
    }

    // ── Copy disassembly ─────────────────────────────────────────────────────

    private fun copyToClipboard() {
        if (buffer.isEmpty()) return
        val sb = StringBuilder()
        for (insn in buffer) {
            sb.append(insn.address.toString(16).uppercase().padStart(16, '0'))
            sb.append("  ")
            // space-separate the byte pairs
            val hex = insn.bytesHex
            val separated = buildString {
                var i = 0
                while (i + 1 < hex.length) { append(hex.substring(i, i + 2)); append(' '); i += 2 }
            }.trim()
            sb.append(separated.padEnd(12))
            sb.append("  ")
            sb.append(insn.mnemonic)
            if (insn.operands.isNotEmpty()) {
                sb.append("  ")
                sb.append(insn.operands)
            }
            sb.append('\n')
        }
        val clip = ClipData.newPlainText("disassembly", sb)
        (requireContext().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager)
            .setPrimaryClip(clip)
        flashCopyButton()
    }

    private fun flashCopyButton() {
        val ctx = context ?: return
        val green = ColorStateList.valueOf(ContextCompat.getColor(ctx, R.color.copy_flash))
        val normal = ColorStateList.valueOf(ContextCompat.getColor(ctx, R.color.text_secondary))
        b.btnCopy.imageTintList = green
        Handler(Looper.getMainLooper()).postDelayed({
            if (_b != null) b.btnCopy.imageTintList = normal
        }, 2000)
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _b = null
    }
}
