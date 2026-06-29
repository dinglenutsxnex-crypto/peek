package com.nex.peek.adapter

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.nex.peek.PeekNative
import com.nex.peek.databinding.ItemRecentBinaryBinding
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class RecentProjectsAdapter(
    private val onClick: (PeekNative.BinaryInfo) -> Unit
) : ListAdapter<PeekNative.BinaryInfo, RecentProjectsAdapter.VH>(DIFF) {

    inner class VH(private val b: ItemRecentBinaryBinding) : RecyclerView.ViewHolder(b.root) {
        fun bind(info: PeekNative.BinaryInfo) {
            b.tvName.text = info.name
            b.tvMeta.text = "${info.funcCount} functions"
            b.tvDate.text = formatDate(info.timestamp)
            b.root.setOnClickListener { onClick(info) }
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) = VH(
        ItemRecentBinaryBinding.inflate(LayoutInflater.from(parent.context), parent, false)
    )

    override fun onBindViewHolder(holder: VH, position: Int) = holder.bind(getItem(position))

    companion object {
        private val DIFF = object : DiffUtil.ItemCallback<PeekNative.BinaryInfo>() {
            override fun areItemsTheSame(a: PeekNative.BinaryInfo, b: PeekNative.BinaryInfo) = a.id == b.id
            override fun areContentsTheSame(a: PeekNative.BinaryInfo, b: PeekNative.BinaryInfo) = a == b
        }

        private val DATE_FMT = SimpleDateFormat("MMM d", Locale.getDefault())
        private val DATE_FMT_YEAR = SimpleDateFormat("MMM d, yyyy", Locale.getDefault())

        fun formatDate(ts: Long): String {
            if (ts == 0L) return ""
            val date = Date(ts * 1000L)
            val now = Date()
            val diffMs = now.time - date.time
            return when {
                diffMs < 60_000L         -> "just now"
                diffMs < 3_600_000L      -> "${diffMs / 60_000}m ago"
                diffMs < 86_400_000L     -> "${diffMs / 3_600_000}h ago"
                diffMs < 172_800_000L    -> "yesterday"
                else -> {
                    val cal = java.util.Calendar.getInstance()
                    val year = cal.get(java.util.Calendar.YEAR)
                    cal.time = date
                    if (cal.get(java.util.Calendar.YEAR) == year) DATE_FMT.format(date)
                    else DATE_FMT_YEAR.format(date)
                }
            }
        }
    }
}
