#include <windows.h>
#include <urlmon.h>
#include <iostream>

#pragma comment(lib, "urlmon.lib")

int main() {
    std::cout << "Attempting network request..." << std::endl;
    HRESULT hr = URLDownloadToFileA(
        NULL,
        "https://www.google.com",
        "google.html",
        0,
        NULL
    );

    if (hr == S_OK) {
        std::cout << "Download successful!" << std::endl;
    } else {
        std::cout << "Download failed with HRESULT: " << hr << std::endl;
    }
    return 0;
}
