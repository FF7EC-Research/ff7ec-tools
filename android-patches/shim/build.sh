#!/bin/sh
# build.sh - builds libff7ec_shim.so (arm64-v8a) and copies the stripped
# result into ../patches/src/main/resources/ff7ec_shim/, where the Morphe
# patch (Ff7ecShimPatch.kt) bundles it from via inputStreamFromBundledResource.
#
# Requires: cmake, and ANDROID_NDK pointing at an installed NDK (r26+ tested).
set -eu
: "${ANDROID_NDK:?set ANDROID_NDK to your NDK install, e.g. /usr/lib/android-ndk}"

cd "$(dirname "$0")"
cmake -B build \
    -DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24 \
    -DCMAKE_BUILD_TYPE=Release .
cmake --build build -- -j"$(nproc)"

out=../patches/src/main/resources/ff7ec_shim
mkdir -p "$out"
"$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip" \
    --strip-all build/libff7ec_shim.so -o "$out/libff7ec_shim.so"
echo "wrote $out/libff7ec_shim.so"
