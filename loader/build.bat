@echo off
REM Build winmm.dll for the FF7 Ever Crisis traffic-inspection loader.
REM Match the game's own bitness (Unity Windows builds are normally x64).
REM
REM Option A: MSVC (open an "x64 Native Tools Command Prompt for VS"), run this.
REM Option B: MinGW (x86_64-w64-mingw32-g++ on PATH); pass "mingw" as arg 1.

if /I "%1"=="mingw" goto mingw

:msvc
echo === Building with MSVC (x64) ===
cl /nologo /LD /O2 /EHsc /DWIN32 /DUNICODE /D_UNICODE ^
   winmm.cpp util.cpp hooks.cpp ssl_bypass.cpp certs.cpp tls_schannel.cpp proxy.cpp decode.cpp ^
   /Fe:winmm.dll /link /DEF:winmm.def ws2_32.lib secur32.lib crypt32.lib ncrypt.lib user32.lib advapi32.lib shell32.lib
if errorlevel 1 exit /b 1
echo Built winmm.dll
goto done

:mingw
echo === Building with MinGW (x86_64) ===
x86_64-w64-mingw32-g++ -shared -O2 -static -std=c++17 -DWIN32 -DUNICODE -D_UNICODE ^
   winmm.cpp util.cpp hooks.cpp ssl_bypass.cpp certs.cpp tls_schannel.cpp proxy.cpp decode.cpp winmm.def ^
   -o winmm.dll -lws2_32 -lsecur32 -lcrypt32 -lncrypt -luser32 -ladvapi32 -lshell32 -Wl,--enable-stdcall-fixup
if errorlevel 1 exit /b 1
echo Built winmm.dll
goto done

:done
echo.
echo Place winmm.dll + ff7ec_loader.ini next to the game's .exe.
