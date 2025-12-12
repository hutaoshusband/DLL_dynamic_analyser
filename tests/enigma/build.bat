@echo off
cl.exe /nologo /EHsc main.cpp /link user32.lib /out:enigma_test.exe
if %errorlevel% neq 0 (
    echo Build failed!
) else (
    echo Build successful: enigma_test.exe
)
