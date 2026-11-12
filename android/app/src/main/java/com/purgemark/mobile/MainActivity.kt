package com.purgemark.mobile

import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import com.purgemark.mobile.core.Challenge
import com.purgemark.mobile.core.Json
import com.purgemark.mobile.core.Posture
import com.purgemark.mobile.core.Record
import com.purgemark.mobile.platform.DeviceState
import com.purgemark.mobile.platform.KeystoreAttestation
import com.purgemark.mobile.platform.Wipe
import java.io.File
import java.time.Instant
import java.time.temporal.ChronoUnit

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) {
                Surface(Modifier.fillMaxSize()) { PurgeMarkFlow(this) }
            }
        }
    }

    /** Creates the attested key and the signed record; also keeps a copy for `adb pull`. */
    fun createRecord(challenge: Challenge): Pair<Json.Obj, File> {
        val createdAt = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString()
        val key = KeystoreAttestation.create(challenge, alias = "purgemark-${System.currentTimeMillis()}")
        val record = Record.build(challenge, DeviceState.identity(), DeviceState.posture(this), createdAt, key)
        val id = (record["record_id"] as Json.Str).value
        val dir = File(getExternalFilesDir(null), "records").apply { mkdirs() }
        val file = File(dir, "purgemark-record-$id.json")
        file.writeText(record.canonical() + "\n")
        return record to file
    }

    fun saveTo(uri: Uri, record: Json.Obj) {
        contentResolver.openOutputStream(uri)?.use { it.write((record.canonical() + "\n").toByteArray()) }
    }
}

private enum class Step { POSTURE, PAIR, PROOF, WIPE }

@Composable
private fun PurgeMarkFlow(activity: MainActivity) {
    var step by remember { mutableStateOf(Step.POSTURE) }
    var record by remember { mutableStateOf<Json.Obj?>(null) }
    var recordFile by remember { mutableStateOf<File?>(null) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var savedElsewhere by remember { mutableStateOf(false) }

    val posture = remember { DeviceState.posture(activity) }
    val identity = remember { DeviceState.identity() }

    fun startProof(challenge: Challenge) {
        busy = true
        error = null
        // Key generation in StrongBox can take seconds: keep it off the UI thread.
        Thread {
            val result = runCatching { activity.createRecord(challenge) }
            activity.runOnUiThread {
                busy = false
                result.onSuccess { (r, f) ->
                    record = r
                    recordFile = f
                    step = Step.PROOF
                }.onFailure { error = "Could not create the proof: ${it.message}" }
            }
        }.start()
    }

    val scan = rememberLauncherForActivityResult(ScanContract()) { result ->
        val text = result.contents ?: return@rememberLauncherForActivityResult
        val challenge = Challenge.fromQr(text)
        if (challenge == null) error = "That QR code isn't a PurgeMark station challenge."
        else startProof(challenge)
    }
    val saveDoc = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        val r = record
        if (uri != null && r != null) {
            runCatching { activity.saveTo(uri, r) }
                .onSuccess { savedElsewhere = true }
                .onFailure { error = "Saving failed: ${it.message}" }
        }
    }
    var adminActive by remember { mutableStateOf(Wipe.isAdminActive(activity)) }
    val requestAdmin = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        adminActive = Wipe.isAdminActive(activity)
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text("PurgeMark", style = MaterialTheme.typography.headlineMedium)
        Text("Verifiable factory reset", style = MaterialTheme.typography.bodyMedium)
        StepIndicator(step)

        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        if (busy) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                CircularProgressIndicator()
                Text("Creating a hardware-backed proof key...")
            }
        }

        when (step) {
            Step.POSTURE -> PostureStep(identity, posture) { step = Step.PAIR }
            Step.PAIR -> PairStep(
                enabled = !busy,
                onScan = {
                    scan.launch(
                        ScanOptions()
                            .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                            .setPrompt("Scan the QR code from `pmark android begin`")
                            .setBeepEnabled(false),
                    )
                },
                onSelf = { startProof(Challenge.selfGenerated()) },
            )
            Step.PROOF -> ProofStep(
                record = record!!,
                localCopy = recordFile,
                savedElsewhere = savedElsewhere,
                onSave = { saveDoc.launch("purgemark-record-${(record!!["record_id"] as Json.Str).value}.json") },
                onContinue = { step = Step.WIPE },
            )
            Step.WIPE -> WipeStep(
                adminActive = adminActive,
                onRequestAdmin = { requestAdmin.launch(Wipe.requestAdminIntent(activity)) },
                onReset = {
                    when (val outcome = Wipe.factoryReset(activity)) {
                        Wipe.Outcome.Started -> error = "Reset requested. If the phone doesn't restart within a minute, use Settings > System > Reset options > Erase all data."
                        is Wipe.Outcome.Failed -> error = outcome.reason +
                            "\nYou can still reset manually: Settings > System > Reset options > Erase all data."
                    }
                },
            )
        }
    }
}

@Composable
private fun StepIndicator(step: Step) {
    val labels = listOf("Check", "Pair", "Proof", "Erase")
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        labels.forEachIndexed { i, label ->
            val current = i == step.ordinal
            Text(
                "${i + 1}. $label",
                style = MaterialTheme.typography.labelLarge,
                color = if (current) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun PostureStep(identity: Record.Device, posture: Posture, onNext: () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("${identity.manufacturer} ${identity.model}", style = MaterialTheme.typography.titleMedium)
            Text("Android ${identity.release} (API ${identity.sdkInt}), security patch ${identity.securityPatch}")
            Text("Storage encryption: ${posture.encryption.wire}")
            Text("Secure lock screen: ${if (posture.secureLockScreen) "yes" else "no"}")
            Text("StrongBox: ${if (posture.strongBoxAvailable) "available" else "not available"}")
        }
    }
    val findings = posture.findings()
    findings.forEach { f ->
        val color = when (f.severity) {
            Posture.Severity.BLOCKER -> MaterialTheme.colorScheme.error
            Posture.Severity.WARNING -> MaterialTheme.colorScheme.tertiary
            Posture.Severity.INFO -> MaterialTheme.colorScheme.onSurfaceVariant
        }
        Text(f.text, color = color)
    }
    val blocked = findings.any { it.severity == Posture.Severity.BLOCKER }
    Button(onClick = onNext, enabled = !blocked, modifier = Modifier.fillMaxWidth()) {
        Text(if (blocked) "This phone can't be crypto-erased" else "Continue")
    }
}

@Composable
private fun PairStep(enabled: Boolean, onScan: () -> Unit, onSelf: () -> Unit) {
    Text("A PurgeMark station issues a one-time challenge so this phone's proof can't be prepared in advance or reused.")
    Button(onClick = onScan, enabled = enabled, modifier = Modifier.fillMaxWidth()) { Text("Scan station QR code") }
    TextButton(onClick = onSelf, enabled = enabled) { Text("No station: use a self-generated challenge (weaker)") }
}

@Composable
private fun ProofStep(
    record: Json.Obj,
    localCopy: File?,
    savedElsewhere: Boolean,
    onSave: () -> Unit,
    onContinue: () -> Unit,
) {
    val key = record["key"] as Json.Obj
    val challenge = record["challenge"] as Json.Obj
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("Proof created", style = MaterialTheme.typography.titleMedium)
            Text("Record ${(record["record_id"] as Json.Str).value}")
            Text("Key: ${(key["security_level"] as Json.Str).value}, ${(key["attestation_chain"] as Json.Arr).items.size} certificates")
            Text("Challenge from: ${(challenge["source"] as Json.Str).value}")
        }
    }
    if ((key["security_level"] as Json.Str).value == "software") {
        Text("Warning: this key is not in secure hardware, so this proof is weak.", color = MaterialTheme.colorScheme.error)
    }
    Text("The record must leave this phone before the reset, which erases everything on it.")
    localCopy?.let {
        Text("Station (USB): adb pull ${it.absolutePath}", fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodySmall)
    }
    OutlinedButton(onClick = onSave, modifier = Modifier.fillMaxWidth()) {
        Text(if (savedElsewhere) "Saved. Save another copy" else "Save record to USB stick or SD card")
    }
    Button(onClick = onContinue, modifier = Modifier.fillMaxWidth()) { Text("Continue to erase") }
}

@Composable
private fun WipeStep(adminActive: Boolean, onRequestAdmin: () -> Unit, onReset: () -> Unit) {
    var handedOver by remember { mutableStateOf(false) }
    var typed by remember { mutableStateOf("") }
    if (!adminActive) {
        Text("PurgeMark needs permission to reset this phone. It asks for nothing else.")
        Button(onClick = onRequestAdmin, modifier = Modifier.fillMaxWidth()) { Text("Allow reset") }
        return
    }
    Text(
        "This erases all data on this phone. With encrypted storage the keys are destroyed, " +
            "making the data unrecoverable.",
        color = MaterialTheme.colorScheme.error,
    )
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = handedOver, onCheckedChange = { handedOver = it })
        Text("The record is saved off this phone")
    }
    OutlinedTextField(value = typed, onValueChange = { typed = it }, label = { Text("Type ERASE to confirm") },
        singleLine = true, modifier = Modifier.fillMaxWidth())
    Spacer(Modifier.height(4.dp))
    Button(
        onClick = onReset,
        enabled = handedOver && typed == "ERASE",
        colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
        modifier = Modifier.fillMaxWidth(),
    ) { Text("Factory reset now") }
}
