@echo off
cl.exe /nologo /EHsc main.cpp user32.lib /link /out:themida_test.exe
if %errorlevel% neq 0 (
    echo Build failed!
) else (
    echo Build successful: themida_test.exe
)
