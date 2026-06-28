package com.nex.peek

import android.Manifest
import android.animation.Animator
import android.animation.AnimatorListenerAdapter
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.TextWatcher
import android.view.Menu
import android.view.MenuItem
import android.view.MotionEvent
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import androidx.core.view.updateLayoutParams
import androidx.core.view.updatePadding
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.tabs.TabLayoutMediator
import com.nex.peek.adapter.FunctionCompactAdapter
import com.nex.peek.adapter.ViewOptionAdapter
import com.nex.peek.databinding.ActivityAnalysisBinding
import com.nex.peek.model.FunctionInfo
import com.nex.peek.ui.AnalysisPagerAdapter
import com.nex.peek.ui.AnalysisSession
import com.nex.peek.ui.AnalysisViewModel
import com.nex.peek.ui.TabId
import com.nex.peek.ui.TabSpec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class AnalysisActivity : AppCompatActivity() {

    private lateinit var b: ActivityAnalysisBinding
    private val vm: AnalysisViewModel by viewModels()
    private lateinit var funcAdapter: FunctionCompactAdapter
    private val allFunctions = mutableListOf<FunctionInfo>()

    // Held while waiting for the user to grant WRITE_EXTERNAL_STORAGE (API < 29).
    private var pendingDownloadType: BulkDownloader.DownloadType? = null

    private val writePermLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        val type = pendingDownloadType ?: return@registerForActivityResult
        pendingDownloadType = null
        if (granted) startDownload(type)
        else Toast.makeText(this, "Storage permission required to save zip", Toast.LENGTH_LONG).show()
    }

    // Which tabs are currently visible, in display order.
    private var activeTabs: MutableList<TabId> = mutableListOf()
    private var tabMediator: TabLayoutMediator? = null

    // Delay (ms) so the click ripple finishes before the content switches
    private val CLICK_SYNC_DELAY_MS = 140L

    override fun onCreate(savedInstanceState: Bundle?) {
        WindowCompat.setDecorFitsSystemWindows(window, false)
        super.onCreate(savedInstanceState)
        b = ActivityAnalysisBinding.inflate(layoutInflater)
        setContentView(b.root)

        // Full immersive: hide both status and nav bars, swipe to reveal transiently.
        WindowInsetsControllerCompat(window, window.decorView).apply {
            hide(WindowInsetsCompat.Type.statusBars())
            hide(WindowInsetsCompat.Type.navigationBars())
            systemBarsBehavior =
                WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            window.isNavigationBarContrastEnforced = false
            window.isStatusBarContrastEnforced = false
        }

        ViewCompat.setOnApplyWindowInsetsListener(b.rootLayout) { _, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            b.toolbar.updatePadding(top = bars.top)
            WindowInsetsCompat.CONSUMED
        }

        setSupportActionBar(b.toolbar)
        supportActionBar?.apply {
            setDisplayHomeAsUpEnabled(false)
            title = intent.getStringExtra(EXTRA_NAME) ?: "PEEK"
        }

        // Load persisted tab set (or defaults) and build the ViewPager.
        activeTabs = loadTabPrefs()
        updateTabs()

        // Dismiss floating dropdowns when tapping outside
        b.rootContainer.setOnClickListener {
            b.viewOptionsContainer.visibility = View.GONE
            b.downloadContainer.visibility = View.GONE
        }

        b.dlHex.setOnClickListener { b.downloadContainer.visibility = View.GONE; initiateDownload(BulkDownloader.DownloadType.HEX) }
        b.dlAsm.setOnClickListener { b.downloadContainer.visibility = View.GONE; initiateDownload(BulkDownloader.DownloadType.ASM) }
        b.dlPseudocode.setOnClickListener { b.downloadContainer.visibility = View.GONE; initiateDownload(BulkDownloader.DownloadType.PSEUDOCODE) }

        funcAdapter = FunctionCompactAdapter { fn ->
            // Delay content switch to sync with the click ripple animation
            Handler(Looper.getMainLooper()).postDelayed({
                vm.selectedFunction.value = fn
            }, CLICK_SYNC_DELAY_MS)
        }
        b.rvFunctions.layoutManager = LinearLayoutManager(this)
        b.rvFunctions.adapter = funcAdapter

        // Scroll hint: show/hide the bottom fade based on scroll position
        b.rvFunctions.addOnScrollListener(object : RecyclerView.OnScrollListener() {
            override fun onScrolled(rv: RecyclerView, dx: Int, dy: Int) {
                val canScrollDown = rv.canScrollVertically(1)
                b.scrollHint.visibility = if (canScrollDown) View.VISIBLE else View.GONE
            }
        })

        b.etSearch.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, st: Int, c: Int, a: Int) {}
            override fun afterTextChanged(s: Editable?) {}
            override fun onTextChanged(s: CharSequence?, st: Int, c: Int, a: Int) {
                val q = s?.toString()?.trim()?.lowercase() ?: ""
                funcAdapter.submitList(
                    if (q.isEmpty()) allFunctions.toList()
                    else allFunctions.filter { it.displayName.lowercase().contains(q) }
                )
                // Re-evaluate scroll hint after filter changes list size
                b.rvFunctions.post {
                    b.scrollHint.visibility =
                        if (b.rvFunctions.canScrollVertically(1)) View.VISIBLE else View.GONE
                }
            }
        })

        setupDividerDrag()

        val handle = AnalysisSession.get()
        if (handle != 0L) {
            val fns = PeekNative.getFunctionList(handle)
            allFunctions.addAll(fns)
            funcAdapter.submitList(fns)
            if (fns.isNotEmpty()) vm.selectedFunction.value = fns[0]
            // Initial scroll hint check after list is laid out
            b.rvFunctions.post {
                b.scrollHint.visibility =
                    if (b.rvFunctions.canScrollVertically(1)) View.VISIBLE else View.GONE
            }
        }
    }

    // ── Toolbar buttons ───────────────────────────────────────────────────────

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menu.add(0, MENU_DOWNLOAD, 0, "Download")
            .setIcon(R.drawable.ic_download)
            .setShowAsAction(MenuItem.SHOW_AS_ACTION_ALWAYS)
        menu.add(0, MENU_VIEW_OPTIONS, 1, "View options")
            .setIcon(R.drawable.ic_view_options)
            .setShowAsAction(MenuItem.SHOW_AS_ACTION_ALWAYS)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            MENU_VIEW_OPTIONS -> { toggleViewOptions(); true }
            MENU_DOWNLOAD     -> { showDownloadMenu(); true }
            else              -> super.onOptionsItemSelected(item)
        }
    }

    // ── Download floating checklist (below toolbar, right-aligned) ─────────────

    private fun showDownloadMenu() {
        if (b.downloadContainer.visibility == View.VISIBLE) {
            b.downloadContainer.visibility = View.GONE
        } else {
            b.viewOptionsContainer.visibility = View.GONE
            b.downloadContainer.visibility = View.VISIBLE
            b.downloadContainer.bringToFront()
        }
    }

    private fun initiateDownload(type: BulkDownloader.DownloadType) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            if (checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE)
                    != PackageManager.PERMISSION_GRANTED) {
                pendingDownloadType = type
                writePermLauncher.launch(Manifest.permission.WRITE_EXTERNAL_STORAGE)
                return
            }
        }
        startDownload(type)
    }

    private fun startDownload(type: BulkDownloader.DownloadType) {
        if (allFunctions.isEmpty()) {
            Toast.makeText(this, "No functions to download", Toast.LENGTH_SHORT).show()
            return
        }
        val handle = AnalysisSession.get()
        if (handle == 0L) {
            Toast.makeText(this, "No binary loaded", Toast.LENGTH_SHORT).show()
            return
        }
        val binaryName = intent.getStringExtra(EXTRA_NAME) ?: "binary"
        val functions  = allFunctions.toList()

        Toast.makeText(
            this,
            "Preparing ${type.label} for ${functions.size} functions…",
            Toast.LENGTH_SHORT
        ).show()

        lifecycleScope.launch {
            val result = runCatching {
                withContext(Dispatchers.IO) {
                    BulkDownloader.downloadAll(
                        context    = applicationContext,
                        handle     = handle,
                        functions  = functions,
                        type       = type,
                        binaryName = binaryName,
                        onProgress = { /* progress available if needed */ }
                    )
                }
            }
            result.onSuccess { filename ->
                Toast.makeText(
                    this@AnalysisActivity,
                    "Saved to Downloads: $filename",
                    Toast.LENGTH_LONG
                ).show()
            }
            result.onFailure { err ->
                Toast.makeText(
                    this@AnalysisActivity,
                    "Download failed: ${err.message}",
                    Toast.LENGTH_LONG
                ).show()
            }
        }
    }

    // ── View options floating dropdown ────────────────────────────────────────

    private fun toggleViewOptions() {
        if (b.viewOptionsContainer.visibility == View.VISIBLE) {
            b.viewOptionsContainer.visibility = View.GONE
        } else {
            b.downloadContainer.visibility = View.GONE
            setupViewOptionsList()
            b.viewOptionsContainer.visibility = View.VISIBLE
            b.viewOptionsContainer.bringToFront()
        }
    }

    private fun setupViewOptionsList() {
        b.rvViewOptions.layoutManager = LinearLayoutManager(this)
        b.rvViewOptions.adapter = ViewOptionAdapter(ALL_TABS, activeTabs) { id ->
            if (activeTabs.contains(id)) {
                if (activeTabs.size > 1) {
                    activeTabs.remove(id)
                }
            } else {
                activeTabs.add(id)
                activeTabs.sortBy { tabId -> ALL_TABS.indexOfFirst { it.id == tabId } }
            }
            updateTabs()
            saveTabPrefs()
            setupViewOptionsList() // Refresh list
        }
    }

    private fun updateTabs() {
        tabMediator?.detach()
        val specs = ALL_TABS.filter { activeTabs.contains(it.id) }
        val adapter = AnalysisPagerAdapter(this, specs)
        b.viewPager.adapter = adapter
        b.viewPager.offscreenPageLimit = specs.size.coerceAtLeast(1)
        tabMediator = TabLayoutMediator(b.tabLayout, b.viewPager) { tab, pos ->
            tab.text = specs[pos].label
        }
        tabMediator?.attach()
    }

    // ── Tab preference persistence ────────────────────────────────────────────

    private fun loadTabPrefs(): MutableList<TabId> {
        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val saved = prefs.getStringSet(PREFS_TABS, null)
        return if (saved != null) {
            ALL_TABS
                .filter { saved.contains(it.id.name) }
                .map { it.id }
                .toMutableList()
                .ifEmpty { mutableListOf(TabId.ASM) }
        } else {
            DEFAULT_VISIBLE.toMutableList()
        }
    }

    private fun saveTabPrefs() {
        getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putStringSet(PREFS_TABS, activeTabs.map { it.name }.toSet())
            .apply()
    }

    // ── Divider drag ──────────────────────────────────────────────────────────

    @SuppressLint("ClickableViewAccessibility")
    private fun setupDividerDrag() {
        val minWidth = resources.getDimensionPixelSize(R.dimen.panel_min_width)
        var startX = 0f
        var startWidth = 0

        b.dividerHandle.setOnTouchListener { view, event ->
            when (event.action) {
                MotionEvent.ACTION_DOWN -> {
                    startX = event.rawX
                    startWidth = b.leftPanel.width
                    b.dividerHandle.setBackgroundColor(
                        resources.getColor(R.color.divider_active, theme)
                    )
                    true
                }
                MotionEvent.ACTION_MOVE -> {
                    val delta = (event.rawX - startX).toInt()
                    val maxWidth = (b.rootLayout.width * 0.5).toInt()
                    val newWidth = (startWidth + delta).coerceIn(minWidth, maxWidth)
                    b.leftPanel.updateLayoutParams { width = newWidth }
                    true
                }
                MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                    b.dividerHandle.setBackgroundColor(
                        resources.getColor(R.color.divider, theme)
                    )
                    view.performClick()
                    true
                }
                else -> false
            }
        }
    }

    companion object {
        const val EXTRA_NAME = "binary_name"

        private const val MENU_DOWNLOAD     = 1002
        private const val MENU_VIEW_OPTIONS = 1001

        private const val DL_HEX        = 2001
        private const val DL_ASM        = 2002
        private const val DL_PSEUDOCODE = 2003

        private const val PREFS_NAME = "peek_prefs"
        private const val PREFS_TABS  = "visible_tabs"

        // Canonical tab order — must stay stable; drives sort order too.
        val ALL_TABS = listOf(
            TabSpec(TabId.ASM,        "ASM"),
            TabSpec(TabId.PSEUDOCODE, "DECOMP"),
            TabSpec(TabId.HEX,        "HEX"),
            TabSpec(TabId.EXPORTS,    "EXPORTS"),
            TabSpec(TabId.IMPORTS,    "IMPORTS")
        )

        // ASM + DECOMP + EXPORTS + IMPORTS on; HEX off by default.
        val DEFAULT_VISIBLE = mutableListOf(TabId.ASM, TabId.PSEUDOCODE, TabId.EXPORTS, TabId.IMPORTS)
    }
}
