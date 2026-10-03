group = "dev.ff7ecpreservation"

patches {
    about {
        name = "FF7EC Preservation Patches"
        description = "Morphe patches for FF7 Ever Crisis: a native traffic-inspection shim " +
            "for preservation research ahead of end of service."
        source = "https://github.com/ff7ec-research/ff7ec-tools"
        author = "ff7ec-research"
        contact = "n/a"
        website = "https://github.com/ff7ec-research/ff7ec-tools"
        license = "MIT"
    }
}

dependencies {
    implementation("app.morphe:morphe-patches-library:1.6.2")
}
