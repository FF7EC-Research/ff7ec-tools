/*
 * FF7 Ever Crisis preservation shim - Morphe patch.
 *
 * Installs libff7ec_shim.so (../../../../shim) into a copy of the game and
 * hooks EntryApplication.attachBaseContext() - the game's own custom
 * Application subclass, confirmed from the installed APK's manifest, and
 * the earliest safe point to System.loadLibrary() from - to load it before
 * any Unity/network code runs.
 *
 * The shim itself (see ../../../../shim/yaha_shim.cpp) hooks the native
 * Cysharp.Net.Http.YetAnotherHttpHandler.Native library this game's
 * MagicOnion/gRPC layer runs over, for: an optional TLS-verification
 * bypass, decrypted on-device traffic logging, and an optional DNS
 * redirect. See ../../../../README.md for the full picture and what each
 * option below does.
 */
package dev.ff7ecpreservation.patches

import app.morphe.patcher.Fingerprint
import app.morphe.patcher.extensions.InstructionExtensions.addInstructions
import app.morphe.patcher.patch.ApkFileType
import app.morphe.patcher.patch.AppTarget
import app.morphe.patcher.patch.Compatibility
import app.morphe.patcher.patch.PatchException
import app.morphe.patcher.patch.booleanOption
import app.morphe.patcher.patch.bytecodePatch
import app.morphe.patcher.patch.resourcePatch
import app.morphe.patcher.patch.stringOption
import app.morphe.util.inputStreamFromBundledResource

private const val PACKAGE_NAME = "com.square_enix.android_googleplay.ff7ecww"
private const val ENTRY_APPLICATION_CLASS =
    "Lcom/square_enix/android_googleplay/ff7ecww/EntryApplication;"
private const val SHIM_LIBRARY_NAME = "libff7ec_shim.so"
private const val SHIM_LIBRARY_ENTRY = "lib/arm64-v8a/$SHIM_LIBRARY_NAME"
private const val CONFIG_ASSET_ENTRY = "assets/ff7ec_shim.cfg"
private const val BRIDGE_INIT_CALL =
    "Ldev/ff7ecpreservation/extension/Ff7ecShimBridge;->init(Landroid/content/Context;)V"

// versionName/versionCode/minSdk/icon color verified against the installed
// XAPK (see ../../../README.md). The game is distributed (at least via
// APKPure, where this was sourced) as an XAPK - a single flat APK won't
// carry the arm64-v8a native split this patch needs - hence XAPK_REQUIRED.
// Only arm64-v8a is supported, matching the shim's own arm64-only build.
private val COMPATIBILITY_FF7EC = Compatibility(
    packageName = PACKAGE_NAME,
    name = "FF7EC",
    description = "Final Fantasy VII Ever Crisis",
    apkFileType = ApkFileType.XAPK_REQUIRED,
    appIconColor = 0xA785E1,
    targets = listOf(
        AppTarget(
            version = "4.0.0",
            versionCode = 126,
            minSdk = 24,
        ),
    ),
)

internal object EntryApplicationAttachBaseContextFingerprint : Fingerprint(
    definingClass = ENTRY_APPLICATION_CLASS,
    name = "attachBaseContext",
    returnType = "V",
    parameters = listOf("Landroid/content/Context;"),
)

/**
 * Bundles the arm64-v8a shim .so (built separately, see ../../../../shim/
 * CMakeLists.txt - this patch does not build it) and writes the config
 * asset the shim reads at startup, from the options below.
 */
private val ff7ecShimFilesPatch = resourcePatch(
    name = "FF7EC network shim (files)",
    description = "Bundles the native preservation shim and its configuration into the APK.",
    // Only ever runs as ff7ecShimPatch's dependency (below), never offered
    // on its own - and a patch with no compatiblePackages ("universal")
    // must default to off.
    default = false,
) {
    val sslBypass by booleanOption(
        key = "sslBypass",
        default = true,
        title = "Disable TLS certificate verification",
        description = "Lets the client accept any TLS certificate, so preservation traffic " +
            "capture works without a trusted cert on this device.",
    )
    val packetLog by booleanOption(
        key = "packetLog",
        default = true,
        title = "Log decrypted traffic",
        description = "Writes decrypted gRPC request/response bodies under the app's own " +
            "external-files folder: Android/data/$PACKAGE_NAME/files/ff7ec_logs/ " +
            "(no storage permission needed - it's the app's own directory).",
    )
    val dnsRedirect by booleanOption(
        key = "dnsRedirect",
        default = false,
        title = "Redirect DNS lookups",
        description = "Redirects the game's own hostname lookups to the Redirect IP below. " +
            "Off by default: traffic logging works without it, since it reads the game's " +
            "own already-decrypted buffers rather than intercepting the connection.",
    )
    val redirectIp by stringOption(
        key = "redirectIp",
        default = "",
        title = "Redirect IP",
        description = "Only used when 'Redirect DNS lookups' is enabled above.",
    )

    execute {
        val shimBytes = inputStreamFromBundledResource("ff7ec_shim", SHIM_LIBRARY_NAME)
            ?.use { it.readBytes() }
            ?: throw PatchException(
                "$SHIM_LIBRARY_NAME was not bundled with this patch - " +
                    "build it first (see ../../../../shim/CMakeLists.txt) and place the " +
                    "result at patches/src/main/resources/ff7ec_shim/$SHIM_LIBRARY_NAME.",
            )
        get(SHIM_LIBRARY_ENTRY, copy = false).writeBytes(shimBytes)

        get(CONFIG_ASSET_ENTRY, copy = false).writeText(
            """
                ssl_bypass=$sslBypass
                packet_log=$packetLog
                dns_redirect=$dnsRedirect
                redirect_ip=${redirectIp.orEmpty()}
            """.trimIndent() + "\n",
        )
    }
}

val ff7ecShimPatch = bytecodePatch(
    name = "FF7EC network shim",
    description = "Installs the FF7 Ever Crisis preservation shim: optional TLS-verification " +
        "bypass, decrypted on-device traffic logging, and an optional DNS redirect.",
    default = true,
) {
    compatibleWith(COMPATIBILITY_FF7EC)
    dependsOn(ff7ecShimFilesPatch)
    // Merges the dex from ../../../../extensions/ff7ec (the Ff7ecShimBridge/
    // ToastRunner classes) into the patched APK - built by the `extension`
    // Gradle plugin block in ../../../extensions/ff7ec/build.gradle.kts.
    extendWith("extensions/ff7ec.mpe")

    execute {
        // Prepend (not replace) the method body: the original attachBaseContext still
        // runs right after, unchanged.
        EntryApplicationAttachBaseContextFingerprint.method.addInstructions(
            0,
            """
                const-string v0, "ff7ec_shim"
                invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
                invoke-static {p0}, $BRIDGE_INIT_CALL
            """,
        )
    }
}
