package com.purgemark.mobile.platform

import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent

/** Device-admin receiver; its only policy is wipe-data (see res/xml/device_admin.xml). */
class PurgeMarkAdmin : DeviceAdminReceiver()

object Wipe {
    fun admin(context: Context) = ComponentName(context, PurgeMarkAdmin::class.java)

    fun isAdminActive(context: Context): Boolean =
        context.getSystemService(DevicePolicyManager::class.java)?.isAdminActive(admin(context)) == true

    /** The system dialog where the user grants device-admin rights. */
    fun requestAdminIntent(context: Context): Intent =
        Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN)
            .putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, admin(context))
            .putExtra(
                DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                "PurgeMark needs this only to trigger the factory reset you confirm.",
            )

    sealed class Outcome {
        /** Android accepted the request; the phone normally restarts straight away. */
        data object Started : Outcome()
        data class Failed(val reason: String) : Outcome()
    }

    /**
     * Factory-resets the device. On encrypted devices this destroys the storage
     * keys, which is the cryptographic erase. Some Android versions restrict
     * wipeData() for plain device admins; the caller then falls back to guiding
     * the user through Settings.
     */
    fun factoryReset(context: Context): Outcome {
        val dpm = context.getSystemService(DevicePolicyManager::class.java)
            ?: return Outcome.Failed("DevicePolicyManager unavailable")
        if (!dpm.isAdminActive(admin(context))) return Outcome.Failed("device admin is not active")
        return try {
            dpm.wipeData(0)
            Outcome.Started
        } catch (e: SecurityException) {
            Outcome.Failed("Android refused the reset: ${e.message}")
        } catch (e: IllegalStateException) {
            Outcome.Failed("Android refused the reset: ${e.message}")
        }
    }
}
