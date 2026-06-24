package com.nex.peek.adapter

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import com.nex.peek.databinding.ItemHexRowBinding

class HexRowAdapter : RecyclerView.Adapter<HexRowAdapter.VH>() {

    data class HexRow(val address: ULong, val bytes: ByteArray)

    private val rows = mutableListOf<HexRow>()

    fun setRows(newRows: List<HexRow>) {
        rows.clear()
        rows.addAll(newRows)
        notifyDataSetChanged()
    }

    inner class VH(private val b: ItemHexRowBinding) : RecyclerView.ViewHolder(b.root) {
        fun bind(row: HexRow) {
            b.tvOffset.text = row.address.toString(16).uppercase().padStart(8, '0')

            val hexSb = StringBuilder()
            val asciiSb = StringBuilder()
            for ((i, byte) in row.bytes.withIndex()) {
                if (i > 0 && i % 4 == 0) hexSb.append(' ')
                hexSb.append(String.format("%02X", byte.toInt() and 0xFF))
                hexSb.append(' ')
                val c = byte.toInt() and 0xFF
                asciiSb.append(if (c in 0x20..0x7E) c.toChar() else '.')
            }
            // Pad hex section to fixed width for alignment
            val padded = hexSb.toString().trimEnd()
            b.tvHex.text = padded
            b.tvAscii.text = asciiSb.toString()
        }
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) = VH(
        ItemHexRowBinding.inflate(LayoutInflater.from(parent.context), parent, false)
    )

    override fun onBindViewHolder(holder: VH, position: Int) = holder.bind(rows[position])
    override fun getItemCount(): Int = rows.size
}
