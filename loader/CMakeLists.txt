# Build the 32-bit winmm.dll preservation loader.
#
# Configure for x86 explicitly, e.g.:
#   MSVC:  cmake -B build -A Win32 && cmake --build build --config Release
#   MinGW: cmake -B build -G "MinGW Makefiles" \
#            -DCMAKE_CXX_COMPILER=i686-w64-mingw32-g++ && cmake --build build
cmake_minimum_required(VERSION 3.15)
project(andapp_loader CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(winmm SHARED
    winmm.cpp
    util.cpp
    hooks.cpp
    helper_server.cpp
    cef_hook.cpp
    winmm.def
)
set_target_properties(winmm PROPERTIES PREFIX "" OUTPUT_NAME "winmm")
target_link_libraries(winmm ws2_32 user32 advapi32)

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(WARNING
        "FF_EXVIUS.exe is 32-bit; configure this build for x86 (e.g. -A Win32).")
endif()

if(MINGW)
    target_link_options(winmm PRIVATE -static -Wl,--enable-stdcall-fixup)
endif()
