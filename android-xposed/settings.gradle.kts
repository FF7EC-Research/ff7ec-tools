rootProject.name = "ff7ec-xposed"

pluginManagement {
    repositories {
        gradlePluginPortal()
        google()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        // XposedBridge API jar (de.robv.android.xposed:api) - LSPosed's own
        // fork of the original Xposed repository, still serving the same
        // compileOnly-only API artifacts every Xposed/LSPosed module builds
        // against.
        maven { url = uri("https://api.xposed.info/") }
    }
}

include(":app")
