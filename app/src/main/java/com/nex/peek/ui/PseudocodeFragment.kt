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
                // --- TEMPORARY BUILD-FINGERPRINT + DIAGNOSTIC MARKER ---
                // peek_jni.cpp now prepends TWO lines when the patched fix runs:
                //   // [PEEK-FIX-MARKER v4] sig_cache=158 c_sigs_for_this_call=157 inferred=yes
                //   // [DIAG] inject_sig is_odd: addr=0x92c8 name=is_odd ... | after followFlow: ... | after pipeline: ...
                // Strip both lines from what's displayed, and show them in a dialog
                // (not a Toast — the diag trace can be long and needs to be read
                // carefully, not glanced at for 2 seconds) so it's possible to
                // pinpoint exactly which stage drops the call, with no adb needed.
                var displayCode = code
                val markerPrefix = "// [PEEK-FIX-MARKER"
                if (code.startsWith(markerPrefix)) {
                    val firstNl = code.indexOf('\n')
                    val markerLine = if (firstNl >= 0) code.substring(0, firstNl) else code
                    val rest = if (firstNl >= 0) code.substring(firstNl + 1) else ""

                    var diagLine = ""
                    displayCode = rest
                    if (rest.startsWith("// [DIAG]")) {
                        val secondNl = rest.indexOf('\n')
                        diagLine = if (secondNl >= 0) rest.substring(0, secondNl) else rest
                        displayCode = if (secondNl >= 0) rest.substring(secondNl + 1) else ""
                    }

                    androidx.appcompat.app.AlertDialog.Builder(requireContext())
                        .setTitle("Fix diagnostic")
                        .setMessage(
                            markerLine.removePrefix("//").trim() +
                            "\n\n" +
                            diagLine.removePrefix("// [DIAG]").trim()
                        )
                        .setPositiveButton("OK", null)
                        .show()
                } else {
                    android.widget.Toast.makeText(
                        requireContext(),
                        "No fix marker found — old build or fix not applied",
                        android.widget.Toast.LENGTH_LONG
                    ).show()
                }
                b.tvPseudocode.text = PseudocodeHighlighter.highlight(displayCode)
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
