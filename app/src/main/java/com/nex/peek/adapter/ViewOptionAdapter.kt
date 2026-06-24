package com.nex.peek.adapter

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import com.nex.peek.databinding.ItemSymbolBinding
import com.nex.peek.ui.TabId
import com.nex.peek.ui.TabSpec

class ViewOptionAdapter(
    private val options: List<TabSpec>,
    private val activeTabs: List<TabId>,
    private val onToggle: (TabId) -> Unit
) : RecyclerView.Adapter<ViewOptionAdapter.VH>() {

    inner class VH(val b: ItemSymbolBinding) : RecyclerView.ViewHolder(b.root)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val b = ItemSymbolBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return VH(b)
    }

    override fun onBindViewHolder(holder: VH, position: Int) {
        val spec = options[position]
        val isActive = activeTabs.contains(spec.id)

        holder.b.tvName.text = spec.label
        holder.b.tvName.textSize = 13f
        holder.b.tvAddress.visibility = android.view.View.GONE
        holder.b.tvType.visibility = android.view.View.GONE

        holder.b.tvBadge.text = if (isActive) "ON" else "OFF"
        holder.b.tvBadge.visibility = android.view.View.VISIBLE

        holder.b.root.setOnClickListener {
            onToggle(spec.id)
        }
    }

    override fun getItemCount() = options.size
}
