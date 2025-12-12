#include <windows.h>
#include <iostream>
#include <vector>
#include <string>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")

bool CheckIsDebuggerPresent() {
    if (IsDebuggerPresent()) {
        std::cout << "[DETECTED] IsDebuggerPresent() returned true." << std::endl;
        return true;
    }
    return false;
}

bool CheckRemoteDebuggerPresent() {
    BOOL isDebuggerPresent = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent) && isDebuggerPresent) {
        std::cout << "[DETECTED] CheckRemoteDebuggerPresent() returned true." << std::endl;
        return true;
    }
    return false;
}

bool CheckTickCount() {
    DWORD start = GetTickCount();
    Sleep(10); 
    DWORD end = GetTickCount();
    
    if ((end - start) > 500) {
        std::cout << "[DETECTED] Time anomaly (GetTickCount): took " << (end - start) << "ms." << std::endl;
        return true;
    }
    return false;
}

bool CheckOutputDebugString() {
    OutputDebugStringA("AntiDebug Check");
    if (GetLastError() == 0) {
    }
    return false;
}

bool CheckFindWindow() {
    const std::vector<std::string> tools = {
        "x64dbg",
        "x32dbg",
        "OllyDbg",
        "Wireshark",
        "Process Hacker"
    };

    bool detected = false;
    for (const auto& tool : tools) {
        if (FindWindowA(NULL, tool.c_str()) || FindWindowA(tool.c_str(), NULL)) {
            std::cout << "[DETECTED] Bad tool window found: " << tool << std::endl;
            detected = true;
        }
    }
    return detected;
}

void BeingDebuggedPeb() {
    std::cout << "[INFO] PEB check skipped in portable C++ source." << std::endl;
}

int main() {
    std::cout << "Starting Anti-Debug Checks..." << std::endl;

    bool detected = false;
    detected |= CheckIsDebuggerPresent();
    detected |= CheckRemoteDebuggerPresent();
    detected |= CheckTickCount();
    detected |= CheckFindWindow();
    CheckOutputDebugString();

    if (detected) {
        std::cout << ">>> DEBUGGER / MALICIOUS TOOL DETECTED <<<" << std::endl;
        MessageBoxA(NULL, "Debugger Detected!", "Security Alert", MB_OK | MB_ICONWARNING);
    } else {
        std::cout << "System appears clean." << std::endl;
        MessageBoxA(NULL, "System Clean", "Status", MB_OK | MB_ICONINFORMATION);
    }

    std::cout << "Press Enter to exit...";
    std::cin.get();

    return 0;
}
