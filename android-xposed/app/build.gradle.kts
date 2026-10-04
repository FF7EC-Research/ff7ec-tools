plugins {
    id("com.android.application")
}

android {
    namespace = "dev.ff7ecpreservation.xposed"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.ff7ecpreservation.xposed"
        minSdk = 27 // LSPosed's own floor
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"

        ndk { abiFilters += "arm64-v8a" }
        externalNativeBuild {
            cmake {
                // Static, not c++_shared: this .so gets dlopen'd into FF7EC's
                // process from a *separate* APK (this module's, via LSPosed),
                // not bundled inside the game's own APK the way the Morphe
                // patch's copy is - no cross-APK libc++_shared.so resolution
                // to rely on this way, fully self-contained instead.
                arguments += "-DANDROID_STL=c++_static"
            }
        }
    }

    externalNativeBuild {
        cmake {
            // Builds the exact same shim sources the Morphe patch bundles
            // (../../android-patches/shim) - one native implementation, two
            // different ways of getting it loaded into the game's process.
            // See that CMakeLists.txt's own comment for why arm64-v8a only.
            path = file("src/main/cpp/CMakeLists.txt")
        }
    }

    // Committed debug.keystore, not a secret - same convention as the
    // debug.keystore Android Studio generates for every developer, with
    // a universally-known password ("android"). Signing release builds
    // with it (rather than leaving them unsigned) means every build, CI
    // or local, has the same signature, so `adb install -r` always works
    // to update an existing install instead of needing an uninstall
    // first. LSPosed itself doesn't care what signs a module.
    signingConfigs {
        create("release") {
            storeFile = file("../debug.keystore")
            storePassword = "android"
            keyAlias = "ff7ecxposed"
            keyPassword = "android"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // lintVitalAnalyzeRelease pulls its own large, unrelated dependency
    // graph (guava et al.) from Maven Central - skip it for this small
    // utility module rather than depend on that resolving cleanly on
    // every release build.
    lint {
        checkReleaseBuilds = false
    }

    // No launcher activity on purpose - an Xposed module is never opened
    // directly, only toggled/scoped from LSPosed's own manager app. It
    // still installs fine as a normal package without one.
    buildFeatures {
        buildConfig = false
    }
}

dependencies {
    compileOnly("de.robv.android.xposed:api:82")
}
