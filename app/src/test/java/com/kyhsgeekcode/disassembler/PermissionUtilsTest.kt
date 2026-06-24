package com.kyhsgeekcode.disassembler

import android.content.Intent
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class PermissionUtilsTest {
    @Test
    fun `storagePermissionsForSdk keeps legacy storage permissions on Android 9 and below`() {
        assertArrayEquals(
            arrayOf(
                android.Manifest.permission.READ_EXTERNAL_STORAGE,
                android.Manifest.permission.WRITE_EXTERNAL_STORAGE
            ),
            storagePermissionsForSdk(28)
        )
    }

    @Test
    fun `storagePermissionsForSdk requests no legacy storage permissions on Android 10 and above`() {
        assertArrayEquals(emptyArray(), storagePermissionsForSdk(29))
        assertArrayEquals(emptyArray(), storagePermissionsForSdk(35))
    }

    @Test
    fun `persistableUriPermissionFlags keeps read grant for content uri with persistable access`() {
        assertEquals(
            Intent.FLAG_GRANT_READ_URI_PERMISSION,
            persistableUriPermissionFlags(
                "content",
                Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
            )
        )
    }

    @Test
    fun `persistableUriPermissionFlags returns zero when persistable access is missing`() {
        assertEquals(
            0,
            persistableUriPermissionFlags(
                "content",
                Intent.FLAG_GRANT_READ_URI_PERMISSION
            )
        )
    }

    @Test
    fun `persistableUriPermissionFlags returns zero for non content uri`() {
        assertEquals(
            0,
            persistableUriPermissionFlags(
                "file",
                Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
            )
        )
    }
}
