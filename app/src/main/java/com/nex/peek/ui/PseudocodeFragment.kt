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
import com.nex.peek.PeekNative
import com.nex.peek.R
import com.nex.peek.databinding.FragmentPseudocodeBinding
import com.nex.peek.model.FunctionInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class PseudocodeFragment : Fragment() {

    private var _b: FragmentPseudocodeBinding? = null
    private val b get() = _b!!

    private val vm: AnalysisViewModel by activityViewModels()
    private var currentFunc: FunctionInfo? = null

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _b = FragmentPseudocodeBinding.inflate(inflater, container, false)
        return b.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        b.btnCopy.setOnClickListener { copyToClipboard() }

        vm.selectedFunction.observe(viewLifecycleOwner) { fn ->
            if (fn != null && fn != currentFunc) loadFunction(fn)
        }
    }

    private fun loadFunction(fn: FunctionInfo) {
        currentFunc = fn
        b.tvPseudocode.text = ""
        b.tvEmpty.visibility = View.GONE
        b.btnCopy.visibility = View.GONE
        b.progressBar.visibility = View.VISIBLE

        lifecycleScope.launch {
            val handle = AnalysisSession.get()
            var code = ""
            var failReason = ""
            withContext(Dispatchers.IO) {
                code = PeekNative.decompileFunction(handle, fn.id)
                if (code.isEmpty()) {
                    failReason = PeekNative.getLastError(handle)
                }
            }
            b.progressBar.visibility = View.GONE
            if (code.isEmpty()) {
                b.tvEmpty.text = if (failReason.isNotEmpty()) {
                    "Decompilation failed\n\n$failReason"
                } else {
                    "Decompilation unavailable"
                }
                b.tvEmpty.visibility = View.VISIBLE
            } else {
                b.tvPseudocode.text = code
                b.btnCopy.visibility = View.VISIBLE
            }
        }
    }

    private fun copyToClipboard() {
        val text = b.tvPseudocode.text.toString()
        if (text.isEmpty()) return
        val clip = ClipData.newPlainText("pseudocode", text)
        (requireContext().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager)
            .setPrimaryClip(clip)
        flashCopyButton()
    }

    private fun flashCopyButton() {
        val ctx = context ?: return
        val green  = ColorStateList.valueOf(ContextCompat.getColor(ctx, R.color.copy_flash))
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
