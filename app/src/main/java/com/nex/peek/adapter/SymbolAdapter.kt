package com.nex.peek.adapter

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.nex.peek.databinding.ItemSymbolBinding
import com.nex.peek.model.SymbolInfo

class SymbolAdapter : ListAdapter<SymbolInfo, SymbolAdapter.VH>(DIFF) {

    inner class VH(private val b: ItemSymbolBinding) : RecyclerView.ViewHolder(b.root) {
        fun bind(s: SymbolInfo) {
            b.tvAddress.text = s.addressHex
            b.tvName.text    = s.name
            b.tvBadge.text   = s.badge
            b.tvType.text    = s.typeStr
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) = VH(
        ItemSymbolBinding.inflate(LayoutInflater.from(parent.context), parent, false)
    )

    override fun onBindViewHolder(holder: VH, position: Int) = holder.bind(getItem(position))

    companion object {
        val DIFF = object : DiffUtil.ItemCallback<SymbolInfo>() {
            override fun areItemsTheSame(a: SymbolInfo, b: SymbolInfo) = a.address == b.address && a.name == b.name
            override fun areContentsTheSame(a: SymbolInfo, b: SymbolInfo) = a == b
        }
    }
}
