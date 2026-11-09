package com.purgemark.mobile.core

/** What the phone reports about itself before the wipe. */
data class Posture(
    val encryption: Encryption,
    val secureLockScreen: Boolean,
    val strongBoxAvailable: Boolean,
    val adbEnabled: Boolean,
) {
    enum class Encryption(val wire: String) {
        FILE_BASED("file-based"),
        FULL_DISK("full-disk"),
        NONE("none"),
        UNKNOWN("unknown"),
    }

    /** A factory reset is a cryptographic erase only when user data is encrypted. */
    val resetIsCryptoErase: Boolean
        get() = encryption == Encryption.FILE_BASED || encryption == Encryption.FULL_DISK

    enum class Severity { BLOCKER, WARNING, INFO }
    data class Finding(val severity: Severity, val text: String)

    fun findings(): List<Finding> = buildList {
        when (encryption) {
            Encryption.NONE -> add(
                Finding(Severity.BLOCKER, "Storage is not encrypted: a factory reset would not be a cryptographic erase.")
            )
            Encryption.UNKNOWN -> add(Finding(Severity.WARNING, "Could not determine the storage encryption state."))
            else -> Unit
        }
        if (!strongBoxAvailable) {
            add(Finding(Severity.INFO, "No StrongBox on this phone. The proof key will use the TEE if there is one."))
        }
        if (adbEnabled) {
            add(Finding(Severity.INFO, "USB debugging is on. That's fine for station mode; the reset turns it off."))
        }
    }

    fun toJson(): Json = Json.obj(
        "encryption" to Json.str(encryption.wire),
        "secure_lock_screen" to Json.bool(secureLockScreen),
        "strongbox_available" to Json.bool(strongBoxAvailable),
        "adb_enabled" to Json.bool(adbEnabled),
    )
}
