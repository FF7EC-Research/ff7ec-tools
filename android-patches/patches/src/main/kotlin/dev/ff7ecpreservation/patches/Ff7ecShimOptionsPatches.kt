/*
 * The FF7EC network shim's three features, each its own independently
 * selectable patch (matching how crimera/piko lists per-feature toggles
 * rather than bundling everything behind one patch's option dialog) -
 * see Ff7ecShimPatch.kt for the shim itself. Each one `dependsOn`
 * ff7ecShimPatch, which transitively guarantees ff7ecShimFilesPatch has
 * already created the (possibly empty) config asset these append a line
 * to - a patch the user leaves unselected simply never runs, so its line
 * is absent and the shim's own defaults (shim/config.h) apply instead.
 */
package dev.ff7ecpreservation.patches

import app.morphe.patcher.patch.resourcePatch
import app.morphe.patcher.patch.stringOption

val ff7ecSslBypassPatch = resourcePatch(
    name = "Disable TLS certificate verification",
    description = "Lets the client accept any TLS certificate, so preservation traffic capture " +
        "works without a trusted cert on this device.",
    default = true,
) {
    compatibleWith(COMPATIBILITY_FF7EC)
    dependsOn(ff7ecShimPatch)

    execute {
        get(CONFIG_ASSET_ENTRY, copy = false).appendText("ssl_bypass=true\n")
    }
}

val ff7ecPacketLogPatch = resourcePatch(
    name = "Log decrypted traffic",
    description = "Writes decrypted gRPC request/response bodies under the app's own " +
        "external-files folder: Android/data/$PACKAGE_NAME/files/ff7ec_logs/ (no storage " +
        "permission needed - it's the app's own directory).",
    default = true,
) {
    compatibleWith(COMPATIBILITY_FF7EC)
    dependsOn(ff7ecShimPatch)

    execute {
        get(CONFIG_ASSET_ENTRY, copy = false).appendText("packet_log=true\n")
    }
}

val ff7ecDnsRedirectPatch = resourcePatch(
    name = "Redirect DNS lookups",
    description = "Redirects the game's own hostname lookups to the Redirect IP option below. " +
        "Off by default: traffic logging works without it, since it reads the game's own " +
        "already-decrypted buffers rather than intercepting the connection - only enable this " +
        "if you specifically need the game to connect somewhere else.",
    default = false,
) {
    val redirectIp by stringOption(
        key = "redirectIp",
        default = null,
        title = "Redirect IP",
        description = "The IP address to redirect the game's own hostname lookups to.",
        required = true,
    ) { ip -> !ip.isNullOrBlank() }

    compatibleWith(COMPATIBILITY_FF7EC)
    dependsOn(ff7ecShimPatch)

    execute {
        get(CONFIG_ASSET_ENTRY, copy = false).appendText(
            "dns_redirect=true\nredirect_ip=$redirectIp\n",
        )
    }
}
