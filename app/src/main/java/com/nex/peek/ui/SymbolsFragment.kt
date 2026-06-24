package com.nex.peek.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.res.ColorStateList
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import com.nex.peek.PeekNative
import com.nex.peek.R
import com.nex.peek.adapter.SymbolAdapter
import com.nex.peek.databinding.FragmentSymbolsListBinding
import com.nex.peek.model.SymbolInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class SymbolsFragment : Fragment() {

    private var _b: FragmentSymbolsListBinding? = null
    private val b get() = _b!!

    private var showImports: Boolean = false
    private var allSymbols: List<SymbolInfo> = emptyList()
    private lateinit var adapter: SymbolAdapter

    companion object {
        private const val ARG_IMPORTS = "show_imports"
        fun newInstance(showImports: Boolean) = SymbolsFragment().apply {
            arguments = Bundle().apply { putBoolean(ARG_IMPORTS, showImports) }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        showImports = arguments?.getBoolean(ARG_IMPORTS, false) ?: false
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _b = FragmentSymbolsListBinding.inflate(inflater, container, false)
        return b.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        adapter = SymbolAdapter()
        b.rvSymbols.layoutManager = LinearLayoutManager(requireContext())
        b.rvSymbols.adapter = adapter
        b.progressBar.visibility = View.VISIBLE

        b.etSearch.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, st: Int, c: Int, a: Int) {}
            override fun afterTextChanged(s: Editable?) {}
            override fun onTextChanged(s: CharSequence?, st: Int, c: Int, a: Int) {
                val q = s?.toString()?.trim()?.lowercase() ?: ""
                filterAndSubmit(q)
            }
        })

        b.btnCopy.setOnClickListener { copyToClipboard() }

        lifecycleScope.launch {
            val handle = AnalysisSession.get()
            allSymbols = withContext(Dispatchers.IO) {
                PeekNative.getSymbols(handle).filter { it.isImport == showImports }
            }
            b.progressBar.visibility = View.GONE
            if (allSymbols.isEmpty()) {
                b.tvEmpty.text = if (showImports) "No imports" else "No exports"
                b.tvEmpty.visibility = View.VISIBLE
            } else {
                adapter.submitList(allSymbols)
                b.btnCopy.visibility = View.VISIBLE
            }
        }
    }

    private fun filterAndSubmit(query: String) {
        if (allSymbols.isEmpty()) return
        val filtered = if (query.isEmpty()) {
            allSymbols
        } else {
            allSymbols.filter { s ->
                s.name.contains(query, ignoreCase = true) ||
                s.addressHex.contains(query, ignoreCase = true)
            }
        }
        if (filtered.isEmpty()) {
            adapter.submitList(emptyList())
            b.tvEmpty.text = "No results"
            b.tvEmpty.visibility = View.VISIBLE
        } else {
            b.tvEmpty.visibility = View.GONE
            adapter.submitList(filtered)
        }
    }

    // ── Copy symbols ─────────────────────────────────────────────────────────

    private fun copyToClipboard() {
        val visible = adapter.currentList
        if (visible.isEmpty()) return
        val sb = StringBuilder()
        for (sym in visible) {
            sb.append(sym.addressHex)
            sb.append("  ")
            sb.append(sym.name)
            sb.append('\n')
        }
        val label = if (showImports) "imports" else "exports"
        val clip = ClipData.newPlainText(label, sb)
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
