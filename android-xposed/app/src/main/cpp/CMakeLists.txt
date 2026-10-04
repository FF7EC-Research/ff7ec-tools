# CMakeLists.txt - builds libff7ec_shim.so for the Xposed module.
#
# Reuses ../../../../../android-patches/shim/*.cpp as-is (the dlsym
# interposition / YAHA hooking logic doesn't care whether it ended up in
# the process via a bytecode-patched attachBaseContext or an Xposed
# handleLoadPackage hook - same effect once attached). Nothing in that
# directory is copied or forked; this just points CMake at the same
# sources so there's one native implementation, not two to keep in sync.
cmake_minimum_required(VERSION 3.22)
project(ff7ec_shim CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SHIM_SRC ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../android-patches/shim)

add_library(ff7ec_shim SHARED
    ${SHIM_SRC}/bridge.cpp
    ${SHIM_SRC}/android_bridge.cpp
    ${SHIM_SRC}/config.cpp
    ${SHIM_SRC}/log_file.cpp
    ${SHIM_SRC}/elf_hook.cpp
    ${SHIM_SRC}/dns_hook.cpp
    ${SHIM_SRC}/yaha_shim.cpp
    ${SHIM_SRC}/protobuf_dump.cpp
    # This module's own, not shared - see its own comment.
    xposed_config.cpp
)
target_include_directories(ff7ec_shim PRIVATE ${SHIM_SRC})
target_link_libraries(ff7ec_shim log android)

# bridge.cpp's FF7EC_DIAG_STAGE bisection (see android-patches's own
# README) is currently checked in at stage 0 there - this build needs the
# real thing regardless of where that separate investigation landed.
target_compile_definitions(ff7ec_shim PRIVATE FF7EC_DIAG_STAGE=5)

if(NOT ANDROID_ABI STREQUAL "arm64-v8a")
    message(WARNING "This shim only targets arm64-v8a; got ${ANDROID_ABI}.")
endif()
