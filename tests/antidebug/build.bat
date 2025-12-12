@echo off
cl.exe /nologo /EHsc main.cpp user32.lib /link /out:antidebug_test.exe
if %errorlevel% neq 0 (
    echo Build failed!
) else (
    echo Build successful: antidebug_test.exe
)
