@echo off
REM Verbose build script for Windows
REM Builds the workspace in release with aggressive size & performance flags

setlocal
echo.
echo [build.bat] Starting verbose release build with aggressive RUSTFLAGS
echo.

where cargo >nul 2>&1
if errorlevel 1 (
  echo ERROR: cargo not found in PATH. Please install Rust and add cargo to PATH.
  pause
  exit /b 1
)

echo Rust/Cargo versions:
rustc --version --verbose
cargo --version --verbose

REM Detect host triple to determine MSVC vs GNU toolchain
for /f "tokens=2 delims=:" %%a in ('rustc -Vv ^| findstr /C:"host:"') do set "HOST_TRIPLE=%%a"
set "HOST_TRIPLE=%HOST_TRIPLE: =%"
echo Host triple: %HOST_TRIPLE%

echo Checking for MSVC in host triple...
echo %HOST_TRIPLE% | findstr /i "msvc" >nul
if %errorlevel%==0 (
  set "MSVC=1"
  echo MSVC detected
) else (
  set "MSVC=0"
  echo Non-MSVC toolchain detected
)

REM Base aggressive flags: size-oriented opt-level, single codegen unit, panic=abort
set "RUSTFLAGS=-C opt-level=z -C codegen-units=1 -C panic=abort"

REM NOTE: On MSVC toolchain, `-C lto` can conflict with `-C embed-bitcode=no` (seen in build scripts).
REM Avoid global LTO on MSVC to prevent build-script/proc-macro failures; keep LTO for GNU toolchains.
if %MSVC%==1 (
  REM MSVC: add linker optimizations but avoid -C lto
  set "RUSTFLAGS=%RUSTFLAGS% -C link-arg=/OPT:REF -C link-arg=/OPT:ICF -C link-arg=/INCREMENTAL:NO"
) else (
  REM Non-MSVC: enable full LTO and request stripped output
  set "RUSTFLAGS=%RUSTFLAGS% -C lto=fat -C link-arg=-s"
)

echo RUSTFLAGS=%RUSTFLAGS%
set "RUSTFLAGS=%RUSTFLAGS%"

echo.
echo Running: cargo build --release -v
echo.

cargo build --release -v
if errorlevel 1 (
  echo.
  echo Build failed.
  pause
  exit /b 1
)

echo.
echo Build finished successfully.

REM Try to strip binaries (best-effort, will skip if tools aren't available)
if %MSVC%==1 (
  echo Skipping automatic strip for MSVC builds (tooling varies).
) else (
  echo Attempting to strip generated binaries in target\release (if `strip` is available)...
  for /f "delims=" %%F in ('dir /b /s target\release\*.exe 2^>nul') do (
    echo Stripping "%%~fF"
    strip "%%~fF" 2>nul || echo strip not found; skipping "%%~fF"
  )
)

echo.
echo Done. Press any key to exit.
pause
endlocal
@echo off
REM Verbose build script for Windows
REM Builds the workspace in release with aggressive size & performance flags

setlocal
echo.
echo [build.bat] Starting verbose release build with aggressive RUSTFLAGS
echo.

where cargo >nul 2>&1
if errorlevel 1 (
  echo ERROR: cargo not found in PATH. Please install Rust and add cargo to PATH.
  pause
  exit /b 1
)

echo Rust/Cargo versions:
rustc --version --verbose
cargo --version --verbose

REM Detect host triple to determine MSVC vs GNU toolchain
for /f "tokens=2 delims=:" %%a in ('rustc -Vv ^| findstr /C:"host:"') do set "HOST_TRIPLE=%%a"
set "HOST_TRIPLE=%HOST_TRIPLE: =%"
echo Host triple: %HOST_TRIPLE%

echo Checking for MSVC in host triple...
echo %HOST_TRIPLE% | findstr /i "msvc" >nul
if %errorlevel%==0 (
  set "MSVC=1"
  echo MSVC detected
) else (
  set "MSVC=0"
  echo Non-MSVC toolchain detected
)

REM Base aggressive flags: size-oriented opt-level, single codegen unit, panic=abort
set "RUSTFLAGS=-C opt-level=z -C codegen-units=1 -C panic=abort"

REM NOTE: On MSVC toolchain, `-C lto` can conflict with `-C embed-bitcode=no` (seen in build scripts).
REM Avoid global LTO on MSVC to prevent build-script/proc-macro failures; keep LTO for GNU toolchains.
if %MSVC%==1 (
  REM MSVC: add linker optimizations but avoid -C lto
  set "RUSTFLAGS=%RUSTFLAGS% -C link-arg=/OPT:REF -C link-arg=/OPT:ICF -C link-arg=/INCREMENTAL:NO"
) else (
  REM Non-MSVC: enable full LTO and request stripped output
  set "RUSTFLAGS=%RUSTFLAGS% -C lto=fat -C link-arg=-s"
)

echo RUSTFLAGS=%RUSTFLAGS%
set "RUSTFLAGS=%RUSTFLAGS%"

echo.
echo Running: cargo build --release -v
echo.

cargo build --release -v
if errorlevel 1 (
  echo.
  echo Build failed.
  pause
  exit /b 1
)

echo.
echo Build finished successfully.

REM Try to strip binaries (best-effort, will skip if tools aren't available)
if %MSVC%==1 (
  echo Skipping automatic strip for MSVC builds (tooling varies).
) else (
  echo Attempting to strip generated binaries in target\release (if `strip` is available)...
  for /f "delims=" %%F in ('dir /b /s target\release\*.exe 2^>nul') do (
    echo Stripping "%%~fF"
    strip "%%~fF" 2>nul || echo strip not found; skipping "%%~fF"
  )
)

echo.
echo Done. Press any key to exit.
pause
endlocal
