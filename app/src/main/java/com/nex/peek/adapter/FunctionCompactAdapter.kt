package com.nex.peek.adapter

import android.graphics.Typeface
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.nex.peek.R
import com.nex.peek.databinding.ItemFunctionCompactBinding
import com.nex.peek.model.FunctionInfo

class FunctionCompactAdapter(
    private val onClick: (FunctionInfo) -> Unit
) : ListAdapter<FunctionInfo, FunctionCompactAdapter.VH>(DIFF) {

    private var selectedPosition = -1

    inner class VH(private val b: ItemFunctionCompactBinding) :
        RecyclerView.ViewHolder(b.root) {

        fun bind(fn: FunctionInfo, selected: Boolean) {
            b.tvAddr.text = fn.address.toString(16).uppercase().padStart(8, '0')
            b.tvName.text = fn.displayName
            b.root.isSelected = selected
            b.root.alpha = if (selected) 1.0f else 0.85f

            // Color name by function kind:
            //   kind 2 → thunk (j_) — muted magenta (IDA pink)
            //   kind 1 → named real symbol — primary text, bold
            //   kind 0 → auto-discovered sub_ — dimmed secondary text
            val (nameColor, bold) = when (fn.kind) {
                2    -> ContextCompat.getColor(b.root.context, R.color.fn_thunk) to false
                1    -> ContextCompat.getColor(b.root.context, R.color.text_primary) to true
                else -> ContextCompat.getColor(b.root.context, R.color.fn_local) to false
            }
            b.tvName.setTextColor(nameColor)
            b.tvName.typeface = if (bold) Typeface.DEFAULT_BOLD else Typeface.DEFAULT

            b.root.setOnClickListener {
                val prev = selectedPosition
                selectedPosition = bindingAdapterPosition
                if (prev >= 0) notifyItemChanged(prev)
                notifyItemChanged(selectedPosition)
                onClick(fn)
            }
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) = VH(
        ItemFunctionCompactBinding.inflate(LayoutInflater.from(parent.context), parent, false)
    )

    override fun onBindViewHolder(holder: VH, position: Int) {
        holder.bind(getItem(position), position == selectedPosition)
    }

    companion object {
        val DIFF = object : DiffUtil.ItemCallback<FunctionInfo>() {
            override fun areItemsTheSame(a: FunctionInfo, b: FunctionInfo) = a.id == b.id
            override fun areContentsTheSame(a: FunctionInfo, b: FunctionInfo) = a == b
        }
    }
}
