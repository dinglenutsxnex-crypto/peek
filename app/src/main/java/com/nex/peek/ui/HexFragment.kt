package com.nex.peek.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.res.ColorStateList
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
import com.nex.peek.PeekNative
import com.nex.peek.R
import com.nex.peek.adapter.HexRowAdapter
import com.nex.peek.databinding.FragmentHexBinding
import com.nex.peek.model.FunctionInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class HexFragment : Fragment() {

    private var _b: FragmentHexBinding? = null
    private val b get() = _b!!
    private val vm: AnalysisViewModel by activityViewModels()
    private lateinit var hexAdapter: HexRowAdapter

    // Keep a local copy of current rows so the copy button can format them.
    private var currentRows: List<HexRowAdapter.HexRow> = emptyList()

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _b = FragmentHexBinding.inflate(inflater, container, false)
        return b.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        hexAdapter = HexRowAdapter()
        b.rvHex.layoutManager = LinearLayoutManager(requireContext())
        b.rvHex.adapter = hexAdapter

        b.btnCopy.setOnClickListener { copyToClipboard() }

        vm.selectedFunction.observe(viewLifecycleOwner) { fn ->
            if (fn != null) loadHex(fn)
        }
    }

    private fun loadHex(fn: FunctionInfo) {
        b.tvEmpty.visibility = View.GONE
        b.btnCopy.visibility = View.GONE
        b.progressBar.visibility = View.VISIBLE
        hexAdapter.setRows(emptyList())
        currentRows = emptyList()

        lifecycleScope.launch {
            val handle = AnalysisSession.get()
            val rows = withContext(Dispatchers.IO) {
                buildHexRows(handle, fn)
            }
            b.progressBar.visibility = View.GONE
            if (rows.isEmpty()) {
                b.tvEmpty.text = "No data for ${fn.displayName}"
                b.tvEmpty.visibility = View.VISIBLE
            } else {
                currentRows = rows
                hexAdapter.setRows(rows)
                b.btnCopy.visibility = View.VISIBLE
            }
        }
    }

    private fun buildHexRows(handle: Long, fn: FunctionInfo): List<HexRowAdapter.HexRow> {
        val insns = PeekNative.getInstructions(handle, fn.id, limit = 100_000, offset = 0)
        if (insns.isEmpty()) return emptyList()

        val allBytes = mutableListOf<Byte>()
        val baseAddr = insns.first().address
        for (insn in insns) {
            val hex = insn.bytesHex
            var i = 0
            while (i + 1 < hex.length) {
                allBytes.add(hex.substring(i, i + 2).toInt(16).toByte())
                i += 2
            }
        }

        val result = mutableListOf<HexRowAdapter.HexRow>()
        val bytes = allBytes.toByteArray()
        val rowSize = 8
        var offset = 0
        while (offset < bytes.size) {
            val end = minOf(offset + rowSize, bytes.size)
            val chunk = bytes.copyOfRange(offset, end)
            result.add(HexRowAdapter.HexRow(baseAddr + offset.toULong(), chunk))
            offset += rowSize
        }
        return result
    }

    // ── Copy hex ─────────────────────────────────────────────────────────────

    private fun copyToClipboard() {
        if (currentRows.isEmpty()) return
        val sb = StringBuilder()
        for (row in currentRows) {
            sb.append(row.address.toString(16).uppercase().padStart(16, '0'))
            sb.append("  ")
            sb.append(row.bytes.joinToString(" ") { "%02X".format(it) })
            sb.append('\n')
        }
        val clip = ClipData.newPlainText("hex", sb)
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
