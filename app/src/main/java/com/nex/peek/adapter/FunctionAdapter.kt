package com.nex.peek.adapter

import android.graphics.Typeface
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.nex.peek.R
import com.nex.peek.databinding.ItemFunctionBinding
import com.nex.peek.model.FunctionInfo

class FunctionAdapter(
    private val onClick: (FunctionInfo) -> Unit
) : ListAdapter<FunctionInfo, FunctionAdapter.VH>(DIFF) {

    inner class VH(private val b: ItemFunctionBinding) : RecyclerView.ViewHolder(b.root) {
        fun bind(fn: FunctionInfo) {
            b.tvAddress.text = fn.addressHex
            b.tvName.text    = fn.displayName
            b.tvSize.text    = "${fn.size} B"

            val (nameColor, bold) = when (fn.kind) {
                2    -> ContextCompat.getColor(b.root.context, R.color.fn_thunk) to false
                1    -> ContextCompat.getColor(b.root.context, R.color.text_primary) to true
                else -> ContextCompat.getColor(b.root.context, R.color.fn_local) to false
            }
            b.tvName.setTextColor(nameColor)
            b.tvName.typeface = if (bold) Typeface.DEFAULT_BOLD else Typeface.DEFAULT

            b.root.setOnClickListener { onClick(fn) }
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) = VH(
        ItemFunctionBinding.inflate(LayoutInflater.from(parent.context), parent, false)
    )

    override fun onBindViewHolder(holder: VH, position: Int) = holder.bind(getItem(position))

    companion object {
        val DIFF = object : DiffUtil.ItemCallback<FunctionInfo>() {
            override fun areItemsTheSame(a: FunctionInfo, b: FunctionInfo) = a.id == b.id
            override fun areContentsTheSame(a: FunctionInfo, b: FunctionInfo) = a == b
        }
    }
}
