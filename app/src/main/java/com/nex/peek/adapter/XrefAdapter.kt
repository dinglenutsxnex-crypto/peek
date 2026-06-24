package com.nex.peek.adapter

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.nex.peek.databinding.ItemXrefBinding
import com.nex.peek.model.XrefInfo

class XrefAdapter(
    private val pivotAddress: ULong,
    private val onClick: (XrefInfo) -> Unit = {}
) : ListAdapter<XrefInfo, XrefAdapter.VH>(DIFF) {

    inner class VH(private val b: ItemXrefBinding) : RecyclerView.ViewHolder(b.root) {
        fun bind(x: XrefInfo) {
            val isIncoming = x.toAddress == pivotAddress
            b.tvDirection.text = if (isIncoming) "←" else "→"
            b.tvFrom.text      = x.fromHex
            b.tvTo.text        = x.toHex
            b.tvType.text      = x.typeLabel
            b.root.setOnClickListener { onClick(x) }
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) = VH(
        ItemXrefBinding.inflate(LayoutInflater.from(parent.context), parent, false)
    )

    override fun onBindViewHolder(holder: VH, position: Int) = holder.bind(getItem(position))

    companion object {
        val DIFF = object : DiffUtil.ItemCallback<XrefInfo>() {
            override fun areItemsTheSame(a: XrefInfo, b: XrefInfo) =
                a.fromAddress == b.fromAddress && a.toAddress == b.toAddress
            override fun areContentsTheSame(a: XrefInfo, b: XrefInfo) = a == b
        }
    }
}
