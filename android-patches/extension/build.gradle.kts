// Compiled and merged into the patched APK's dex by the `extendWith(
// "extensions/ff7ec.mpe")` call in ../patches/.../Ff7ecShimPatch.kt - the
// `extension { ... }` block below is the Morphe Gradle plugin's convention
// for declaring that output artifact's name.
extension { name = "extensions/ff7ec.mpe" }

android {
    namespace = "dev.ff7ecpreservation.extension"
    defaultConfig { minSdk = 24 }   // matches the game's own minSdkVersion
}
