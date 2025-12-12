@echo off
cl.exe /nologo /EHsc main.cpp /link /out:network_test.exe
if %errorlevel% neq 0 (
    echo Build failed!
) else (
    echo Build successful: network_test.exe
)
