# Build winmm.dll for the FF7 Ever Crisis traffic-inspection loader.
#
#   MSVC:  cmake -B build -A x64 && cmake --build build --config Release
#   MinGW: cmake -B build -G "MinGW Makefiles" \
#            -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++ && cmake --build build
cmake_minimum_required(VERSION 3.15)
project(ff7ec_loader CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(winmm SHARED
    winmm.cpp
    util.cpp
    hooks.cpp
    ssl_bypass.cpp
    certs.cpp
    tls_schannel.cpp
    proxy.cpp
    decode.cpp
    winmm.def
)
set_target_properties(winmm PROPERTIES PREFIX "" OUTPUT_NAME "winmm")
target_link_libraries(winmm ws2_32 secur32 crypt32 ncrypt user32 advapi32 shell32)

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(WARNING "Unity Windows builds are normally x64; configure this build for x64.")
endif()

if(MINGW)
    target_link_options(winmm PRIVATE -static -Wl,--enable-stdcall-fixup)
endif()
