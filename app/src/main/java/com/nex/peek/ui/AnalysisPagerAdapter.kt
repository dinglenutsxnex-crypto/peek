package com.nex.peek.ui

import androidx.fragment.app.Fragment
import androidx.fragment.app.FragmentActivity
import androidx.viewpager2.adapter.FragmentStateAdapter

class AnalysisPagerAdapter(
    fa: FragmentActivity,
    private val tabs: List<TabSpec>
) : FragmentStateAdapter(fa) {

    override fun getItemCount(): Int = tabs.size

    override fun createFragment(position: Int): Fragment = when (tabs[position].id) {
        TabId.ASM     -> DisassemblyFragment()
        TabId.HEX     -> HexFragment()
        TabId.EXPORTS -> SymbolsFragment.newInstance(showImports = false)
        TabId.IMPORTS -> SymbolsFragment.newInstance(showImports = true)
    }

    // Stable IDs let ViewPager2 reuse existing fragment instances
    // when the tab list changes (rather than destroying all fragments).
    override fun getItemId(position: Int): Long = tabs[position].id.ordinal.toLong()
    override fun containsItem(itemId: Long): Boolean =
        tabs.any { it.id.ordinal.toLong() == itemId }
}
