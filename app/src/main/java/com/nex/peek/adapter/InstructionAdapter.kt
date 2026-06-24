package com.nex.peek.adapter

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.nex.peek.databinding.ItemInstructionBinding
import com.nex.peek.model.InstructionInfo

class InstructionAdapter(
    private val onLongClick: (InstructionInfo) -> Unit = {}
) : ListAdapter<InstructionInfo, InstructionAdapter.VH>(DIFF) {

    inner class VH(private val b: ItemInstructionBinding) : RecyclerView.ViewHolder(b.root) {
        fun bind(insn: InstructionInfo) {
            b.tvOffset.text   = insn.addressHex
            b.tvBytes.text    = insn.bytesFormatted
            b.tvMnemonic.text = insn.mnemonic
            b.tvOperands.text = insn.operands
            b.root.setOnLongClickListener { onLongClick(insn); true }
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) = VH(
        ItemInstructionBinding.inflate(LayoutInflater.from(parent.context), parent, false)
    )

    override fun onBindViewHolder(holder: VH, position: Int) = holder.bind(getItem(position))

    companion object {
        val DIFF = object : DiffUtil.ItemCallback<InstructionInfo>() {
            override fun areItemsTheSame(a: InstructionInfo, b: InstructionInfo) = a.address == b.address
            override fun areContentsTheSame(a: InstructionInfo, b: InstructionInfo) = a == b
        }
    }
}
