#include <windows.h>

int main() {
    MessageBoxA(NULL, "This is protected with Enigma", "Enigma Test", MB_OK | MB_ICONINFORMATION);
    return 0;
}
