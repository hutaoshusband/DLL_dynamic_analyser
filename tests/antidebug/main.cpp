#include <windows.h>
#include <iostream>
#include <vector>
#include <string>

// Link necessary libraries
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
    // Simulate some work, but short enough that human stepping would take much longer
    Sleep(10); 
    DWORD end = GetTickCount();
    
    // If it took more than 500ms (likely a breakpoint), detect it.
    if ((end - start) > 500) {
        std::cout << "[DETECTED] Time anomaly (GetTickCount): took " << (end - start) << "ms." << std::endl;
        return true;
    }
    return false;
}

bool CheckOutputDebugString() {
    // Calling OutputDebugString does not throw error if no debugger, 
    // but SetLastError is sometimes used in older techniques.
    // Modern technique: Check if error code changes (weak) or just rely on API behavior.
    // We will do a simple "try to confuse" or just leave it as a marker.
    OutputDebugStringA("AntiDebug Check");
    if (GetLastError() == 0) {
        // This is often not reliable on its own in modern windows but good for "noise"
        // std::cout << "[INFO] OutputDebugString call completed." << std::endl;
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
    // Direct PEB access via inline assembly or intrinsics is arch specific.
    // For x64, we use __readgsqword(0x60). For x86, __readfsdword(0x30).
    // We will stick to standard APIs for portable simple test, 
    // but detecting the BeingDebugged flag manually is classic.
    
    // Simplified PEB check for x64/x86 using standard winapi definitions if available,
    // or just skipping inline asm to keep this C++ standard compliant for cl.exe easily.
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

    // Keep console open
    std::cout << "Press Enter to exit...";
    std::cin.get();

    return 0;
}
