package com.kyhsgeekcode.disassembler.ui.tabs

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.Column
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import com.kyhsgeekcode.disassembler.project.ProjectDataStorage
import com.kyhsgeekcode.disassembler.ui.TabData
import com.kyhsgeekcode.disassembler.ui.TabKind
import com.kyhsgeekcode.disassembler.ui.components.HexView
import com.kyhsgeekcode.disassembler.ui.components.buildHexPreview
import com.kyhsgeekcode.disassembler.viewmodel.MainViewModel
import androidx.compose.material3.Text
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow


class HexTabData(val data: TabKind.Hex) : PreparedTabData() {
    private val _preview = MutableStateFlow(buildHexPreview(byteArrayOf()))
    val preview = _preview as StateFlow<com.kyhsgeekcode.disassembler.ui.components.HexPreview>

    override suspend fun prepare() {
        _preview.value = buildHexPreview(
            ProjectDataStorage.getFileContentPreview(
                data.relPath,
                com.kyhsgeekcode.disassembler.ui.components.MAX_RENDERED_HEX_BYTES
            )
        )
    }
}


@ExperimentalFoundationApi
@Composable
fun HexTab(data: TabData, viewModel: MainViewModel) {
    val preparedTabData: HexTabData = viewModel.getTabData(data)
    val preview = preparedTabData.preview.collectAsState()
    Column {
        if (preview.value.isTruncated) {
            Text("Showing first ${preview.value.bytes.size} bytes of ${preview.value.originalSize} bytes")
        }
        HexView(bytes = preview.value.bytes)
    }
}
