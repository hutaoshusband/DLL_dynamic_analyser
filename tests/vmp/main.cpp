#include <windows.h>

int main() {
    MessageBoxA(NULL, "This is protected with VMProtect", "VMProtect Test", MB_OK | MB_ICONINFORMATION);
    return 0;
}
