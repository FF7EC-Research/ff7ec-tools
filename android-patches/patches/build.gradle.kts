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

val patchListGeneratorClasspath = configurations.create("patchListGeneratorClasspath")

dependencies {
    implementation("app.morphe:morphe-patches-library:1.6.2")
    patchListGeneratorClasspath("com.google.code.gson:gson:2.11.0")
}

tasks {
    // Regenerates ../patches-list.json for real from the built .mpp's own
    // patch metadata (see app.morphe.util.PatchListGeneratorKt) - matches
    // the pattern real Morphe patch repos use (e.g. kuntal-devrat/diskwala-patches).
    // Invoked by .github/workflows/android-patches-release.yml.
    register<JavaExec>("generatePatchesList") {
        description = "Build the patch bundle, then regenerate patches-list.json from it"
        dependsOn(build)
        classpath = sourceSets["main"].runtimeClasspath + patchListGeneratorClasspath
        mainClass.set("app.morphe.util.PatchListGeneratorKt")
    }
}
