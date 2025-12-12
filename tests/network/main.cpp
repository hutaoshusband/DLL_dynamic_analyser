#define NOMINMAX
#include <windows.h>
#include <urlmon.h>
#include <iostream>
#include <limits>

#pragma comment(lib, "urlmon.lib")

void makeGoogleRequest() {
    std::cout << "\nAttempting to download 'https://www.google.com' to 'google.html'..." << std::endl;

    HRESULT hr = URLDownloadToFileA(
        NULL,
        "https://www.google.com",
        "google.html",
        0,
        NULL
    );

    if (hr == S_OK) {
        std::cout << "Download successful! File saved as 'google.html'." << std::endl;
    } else {
        std::cout << "Download failed with HRESULT: " << hr << std::endl;
    }
}

int main() {
    char choice;

    std::cout << "Google Request Console App" << std::endl;

    while (true) {
        std::cout << "\n---" << std::endl;
        std::cout << "Press 'y' or 'Y' to make a Google request." << std::endl;
        std::cout << "Press 'n' or 'N' to exit the application." << std::endl;
        std::cout << "Enter your choice: ";

        if (!(std::cin >> choice)) {
            break;
        }

        choice = std::tolower(choice);

        if (choice == 'y') {
            makeGoogleRequest();
        } else if (choice == 'n') {
            std::cout << "\nExiting application." << std::endl;
            break;
        } else {
            std::cout << "Invalid choice. Please press 'y' or 'n'." << std::endl;
        }

        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }

    return 0;
}