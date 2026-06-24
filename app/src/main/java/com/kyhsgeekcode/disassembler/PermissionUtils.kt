package com.kyhsgeekcode.disassembler

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.DialogInterface
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi

// ///////////////////////////////////End Show **** dialog///////////////////////////////////////////
// /////////////////////////////////////Permission///////////////////////////////////////////////////
object PermissionUtils {
    val TAG = "PermissionUtils"

    fun requestAppPermissions(a: Activity) {
        val requestedPermissions = storagePermissionsForSdk(Build.VERSION.SDK_INT)
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            (a as MainActivity).onRequestPermissionsResult(
                MainActivity.REQUEST_WRITE_STORAGE_REQUEST_CODE,
                emptyArray(), intArrayOf(PackageManager.PERMISSION_GRANTED)
            )
            return
        }

        if (requestedPermissions.isEmpty()) {
            a.onRequestPermissionsResult(
                MainActivity.REQUEST_WRITE_STORAGE_REQUEST_CODE,
                emptyArray(), intArrayOf(PackageManager.PERMISSION_GRANTED)
            )
            return
        }

        if (hasReadPermissions(a) && hasWritePermissions(a) /*&&hasGetAccountPermissions(a)*/) {
            Log.i(TAG, "Has permissions")
            a.onRequestPermissionsResult(
                MainActivity.REQUEST_WRITE_STORAGE_REQUEST_CODE,
                emptyArray(), intArrayOf(PackageManager.PERMISSION_GRANTED)
            )
            return
        }
        showPermissionRationales(a, Runnable {
            a.requestPermissions(requestedPermissions, MainActivity.REQUEST_WRITE_STORAGE_REQUEST_CODE)
        })
    }

    @RequiresApi(Build.VERSION_CODES.M)
    fun hasGetAccountPermissions(c: Context): Boolean {
        return c.checkSelfPermission(Manifest.permission.GET_ACCOUNTS) == PackageManager.PERMISSION_GRANTED
    }

    fun hasReadPermissions(c: Context): Boolean {
        if (storagePermissionsForSdk(Build.VERSION.SDK_INT).isEmpty()) {
            return true
        }
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            c.checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED
        } else {
            return true
        }
    }

    fun hasWritePermissions(c: Context): Boolean {
        if (storagePermissionsForSdk(Build.VERSION.SDK_INT).isEmpty()) {
            return true
        }
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            c.checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED
        } else {
            return true
        }
    }

    fun showPermissionRationales(a: Activity, run: Runnable?) {
        showAlertDialog(a, a.getString(R.string.permissions),
            a.getString(R.string.permissionMsg),
            DialogInterface.OnClickListener { p1, p2 ->
                run?.run()
                // requestAppPermissions(a);
            })
    }

}

fun storagePermissionsForSdk(sdkInt: Int): Array<String> {
    return if (sdkInt <= Build.VERSION_CODES.P) {
        arrayOf(
            Manifest.permission.READ_EXTERNAL_STORAGE,
            Manifest.permission.WRITE_EXTERNAL_STORAGE
        )
    } else {
        emptyArray()
    }
}

fun persistableUriPermissionFlags(uri: Uri?, intentFlags: Int): Int {
    return persistableUriPermissionFlags(uri?.scheme, intentFlags)
}

fun persistableUriPermissionFlags(uriScheme: String?, intentFlags: Int): Int {
    if (uriScheme != "content") {
        return 0
    }

    if (intentFlags and Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION == 0) {
        return 0
    }

    return intentFlags and (
            Intent.FLAG_GRANT_READ_URI_PERMISSION or
                Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            )
}
