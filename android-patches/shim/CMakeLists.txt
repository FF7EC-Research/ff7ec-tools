# CMakeLists.txt - builds libff7ec_shim.so (arm64-v8a only).
#
#   cmake -B build -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
#         -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24
#   cmake --build build
#
# The Morphe patch (../patches) bundles the resulting .so under
# lib/arm64-v8a/libff7ec_shim.so in the patched APK.
cmake_minimum_required(VERSION 3.22)
project(ff7ec_shim CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(ff7ec_shim SHARED
    bridge.cpp
    android_bridge.cpp
    config.cpp
    log_file.cpp
    elf_hook.cpp
    dns_hook.cpp
    yaha_shim.cpp
    protobuf_dump.cpp
)
target_link_libraries(ff7ec_shim log android)

if(NOT ANDROID_ABI STREQUAL "arm64-v8a")
    message(WARNING "This shim only targets arm64-v8a (the XAPK's only native split); got ${ANDROID_ABI}.")
endif()
