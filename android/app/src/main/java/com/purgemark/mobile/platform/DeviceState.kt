package com.purgemark.mobile.platform

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import com.purgemark.mobile.core.Posture
import com.purgemark.mobile.core.Record

/** Reads identity and security posture. Nothing here needs a runtime permission. */
object DeviceState {
    // Since Android 10 apps can't read the serial number or IMEI; the station
    // reads the serial over ADB and the operator enters the IMEI.
    fun identity(): Record.Device = Record.Device(
        manufacturer = Build.MANUFACTURER,
        brand = Build.BRAND,
        model = Build.MODEL,
        device = Build.DEVICE,
        product = Build.PRODUCT,
        sdkInt = Build.VERSION.SDK_INT,
        release = Build.VERSION.RELEASE,
        securityPatch = Build.VERSION.SECURITY_PATCH,
        fingerprint = Build.FINGERPRINT,
    )

    fun posture(context: Context): Posture {
        val dpm = context.getSystemService(DevicePolicyManager::class.java)
        val keyguard = context.getSystemService(KeyguardManager::class.java)
        val encryption = when (dpm?.storageEncryptionStatus) {
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER -> Posture.Encryption.FILE_BASED
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE,
            DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY -> Posture.Encryption.FULL_DISK
            DevicePolicyManager.ENCRYPTION_STATUS_INACTIVE,
            DevicePolicyManager.ENCRYPTION_STATUS_UNSUPPORTED -> Posture.Encryption.NONE
            else -> Posture.Encryption.UNKNOWN
        }
        return Posture(
            encryption = encryption,
            secureLockScreen = keyguard?.isDeviceSecure == true,
            strongBoxAvailable = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE),
            adbEnabled = Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1,
        )
    }
}
