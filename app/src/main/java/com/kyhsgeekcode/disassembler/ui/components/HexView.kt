package com.kyhsgeekcode.disassembler.ui.components

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp

internal const val BYTES_PER_ROW = 16
private val OFFSET_WIDTH = 90.dp
private val HEX_CELL_WIDTH = 25.dp
private val ASCII_CELL_WIDTH = 12.dp
internal const val MAX_RENDERED_HEX_BYTES = 256 * 1024

data class HexPreview(
    val bytes: ByteArray,
    val originalSize: Int,
    val isTruncated: Boolean
)

fun buildHexPreview(bytes: ByteArray, maxBytes: Int = MAX_RENDERED_HEX_BYTES): HexPreview {
    if (bytes.size <= maxBytes) {
        return HexPreview(bytes = bytes, originalSize = bytes.size, isTruncated = false)
    }
    return HexPreview(
        bytes = bytes.copyOf(maxBytes),
        originalSize = bytes.size,
        isTruncated = true
    )
}

data class HexRow(
    val offset: Int,
    val bytes: List<Byte>,
    val paddedHexValues: List<String>,
    val asciiValues: List<String>
)

fun buildHexRows(bytes: ByteArray): List<HexRow> {
    return bytes.toList().chunked(BYTES_PER_ROW).mapIndexed { index, chunk ->
        val paddedHex = chunk.map { "%02X".format(it.toInt() and 0xFF) } +
            List(BYTES_PER_ROW - chunk.size) { "" }
        val ascii = chunk.map { byte ->
            val charValue = byte.toInt().toChar()
            if (isPrintableChar(charValue)) charValue.toString() else "."
        } + List(BYTES_PER_ROW - chunk.size) { "" }
        HexRow(
            offset = index * BYTES_PER_ROW,
            bytes = chunk,
            paddedHexValues = paddedHex,
            asciiValues = ascii
        )
    }
}

@ExperimentalFoundationApi
@Composable
fun HexView(bytes: ByteArray) {
    val rows by remember(bytes) {
        derivedStateOf { buildHexRows(bytes) }
    }

    LazyColumn(Modifier.horizontalScroll(rememberScrollState())) {
        stickyHeader {
            HexViewHeader()
        }
        items(rows) { row ->
            HexViewRow(row)
        }
    }
}

@Composable
fun HexViewHeader() {
    Row(Modifier.height(IntrinsicSize.Min)) {
        Text(
            text = "Offset",
            modifier = Modifier
                .width(OFFSET_WIDTH)
                .fillMaxHeight()
                .background(Color.White),
            textAlign = TextAlign.Center,
            fontWeight = FontWeight.ExtraBold,
            color = Color.DarkGray
        )
        Spacer(
            modifier = Modifier
                .width(4.dp)
                .fillMaxHeight()
        )
        for (value in 0 until BYTES_PER_ROW) {
            Text(
                text = "%02X".format(value),
                modifier = Modifier
                    .width(HEX_CELL_WIDTH)
                    .fillMaxHeight()
                    .background(Color.White),
                textAlign = TextAlign.Center,
                fontWeight = FontWeight.ExtraBold,
                color = Color.Blue
            )
        }
        Spacer(
            modifier = Modifier
                .width(8.dp)
                .fillMaxHeight()
        )
        for (value in 0 until BYTES_PER_ROW) {
            Text(
                text = value.toString(16).uppercase(),
                modifier = Modifier
                    .width(ASCII_CELL_WIDTH)
                    .fillMaxHeight()
                    .background(Color.White),
                textAlign = TextAlign.Center,
                fontWeight = FontWeight.ExtraBold,
                color = Color.Green
            )
        }
    }
}

@Composable
private fun HexViewRow(row: HexRow) {
    Row(Modifier.height(IntrinsicSize.Min)) {
        Text(
            text = "0x%08X".format(row.offset),
            modifier = Modifier
                .width(OFFSET_WIDTH)
                .fillMaxHeight()
                .background(Color.White),
            textAlign = TextAlign.Center,
            color = Color.DarkGray
        )
        Spacer(
            modifier = Modifier
                .width(4.dp)
                .fillMaxHeight()
        )
        row.paddedHexValues.forEach { hexValue ->
            Text(
                text = hexValue,
                modifier = Modifier
                    .width(HEX_CELL_WIDTH)
                    .fillMaxHeight()
                    .background(Color.White),
                textAlign = TextAlign.Center
            )
        }
        Spacer(
            modifier = Modifier
                .width(8.dp)
                .fillMaxHeight()
        )
        row.asciiValues.forEach { asciiValue ->
            Text(
                text = asciiValue,
                modifier = Modifier
                    .width(ASCII_CELL_WIDTH)
                    .fillMaxHeight()
                    .background(Color.White),
                textAlign = TextAlign.Center
            )
        }
    }
}

fun isPrintableChar(c: Char): Boolean {
    val block = Character.UnicodeBlock.of(c)
    return !Character.isISOControl(c) && block != null && block !== Character.UnicodeBlock.SPECIALS
}

@OptIn(ExperimentalFoundationApi::class)
@Preview
@Composable
fun HexPreview() {
    HexView(
        bytes = byteArrayOf(
            0xFF.toByte(), 0x12.toByte(), 0x13.toByte(), 0x11.toByte(),
            0x40.toByte(), 0x33.toByte(), 0x65.toByte(), 0x55.toByte(),
            0x70.toByte(), 0x59.toByte(), 0x4A.toByte(), 0x2B.toByte(),
            0x1C.toByte(), 0x3D.toByte(), 0xEE.toByte(), 0x7F.toByte(),
            0x00.toByte(), 0xAB.toByte()
        )
    )
}
