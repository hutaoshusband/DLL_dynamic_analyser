@echo off
cl.exe /nologo /EHsc main.cpp user32.lib /link /out:vmp_test.exe
if %errorlevel% neq 0 (
    echo Build failed!
) else (
    echo Build successful: vmp_test.exe
)
