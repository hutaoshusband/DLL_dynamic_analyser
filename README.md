<div align="center">

# DLL Analyser
### Advanced Modular Dynamic Analysis Framework

[![Website](https://img.shields.io/badge/WallbangBros-Website-3b82f6?style=for-the-badge&logo=googlechrome&logoColor=white)](https://wallbangbros.com)
[![Website](https://img.shields.io/badge/FireflyProtector-Website-8b5cf6?style=for-the-badge&logo=googlechrome&logoColor=white)](https://fireflyprotector.xyz)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078d4?style=for-the-badge&logo=windows&logoColor=white)](https://microsoft.com)
[![Built With](https://img.shields.io/badge/Built%20With-Rust-d97757?style=for-the-badge&logo=rust&logoColor=white)](https://rust-lang.org)

<br/>


<img src="https://raw.githubusercontent.com/hutaoshusband/DLL_dynamic_analyser/refs/heads/main/docs/dll-logo.png" alt="DLL Analyser Demo" width="100%" style="border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.5);">

<br/>

<p align="center">
  <b>Stealth Injection</b> • <b>API Hooking</b> • <b>Memory Forensics</b> • <b>VMP Dumping</b>
</p>

</div>

---

## ⚡ Overview

**DLL Analyser** is a sophisticated, modular dynamic analysis tool designed for deep inspection of Windows processes. Built with performance and stealth in mind, it combines a modern, "Frosted Glass" GUI (ios 26 inspired) with a powerful injected core.

Unlike standard debuggers, DLL Analyser operates from within the target process, allowing for:
*   **Real-time API interception** and modification.
*   **Anti-Debug & Anti-VM detection** and bypass.
*   **Memory Forensics** to uncover hidden code (VMP/Packer unpacking).
*   **Network traffic monitoring** at the socket level.

It bridges the gap between static analysis and runtime debugging, wrapped in a visually stunning interface.

## 🚀 Features

### 🛡️ Core Analysis Engine
*   **Advanced API Hooking:** Intercepts critical system calls (`kernel32`, `ntdll`, `user32`, `wininet`) to monitor file I/O, process creation, and network activity.
*   **VMP/Packer Dumper:** Automatically detects and dumps unpacked code sections from protected binaries (VMProtect, etc.).
*   **Memory Scanning:** Scans for manual mapped modules, shellcode injections, and hidden threads.
*   **Entropy Analysis:** Real-time Shannon entropy calculation to identify encrypted or compressed data blocks.

### 🎨 Modern "Clear Glass" UI
*   **ios 26 Aesthetic:** A clean, translucent interface designed for clarity and focus.
*   **Real-time Data Visualization:** Live graphs for entropy and memory usage.
*   **Interactive Logger:** Color-coded, searchable logs with stack trace support.
*   **Configurable Profiles:** Switch between `Stealth`, `Balanced`, and `Aggressive` monitoring modes instantly.

### 🔌 Connectivity & Control
*   **Robust IPC:** Uses secure named pipes for high-speed communication between the loader and the target.
*   **Remote Configuration:** Update hooks and settings on-the-fly without restarting the target process.

## 🛠️ Installation

### Prerequisites
*   **Rust Toolchain:** Ensure you have the latest stable Rust installed (`rustup update`).
*   **Windows Build Tools:** C++ build tools via Visual Studio Installer.

### Build from Source
Clone the repository and build the workspace:

```bash
# Clone the repository
git clone https://github.com/hutaoshusband/DLL_dynamic_analyser
cd DLL_dynamic_analyzer

# Build the entire workspace (Loader + Client + Shared)
cargo build --release --workspace
```

> **Note:** The output binaries will be located in `target/release/`. You will need both `loader.exe` and `client.dll`.

## 🎮 Usage

1.  **Launch the Loader:**
    Run `loader.exe` as Administrator to ensure sufficient privileges for process injection.

2.  **Select Target:**
    Use the "Injector" tab to select the target process or launch a new executable.

3.  **Inject:**
    Click **Inject**. The `client.dll` will be loaded into the target.

4.  **Monitor:**
    Switch to the **Logs** tab to see real-time events.
    Use the **Scanner** tab to perform memory dumps or entropy checks.

## 📦 Project Structure

| Crate | Description |
| :--- | :--- |
| **`loader`** | The GUI frontend (egui). Handles injection, configuration, and log display. |
| **`client`** | The injected DLL. Performs hooking, scanning, and data collection. |
| **`shared`** | Common types, IPC command definitions, and configuration structs. |

## ⚠️ Disclaimer

This tool is intended for **educational and security research purposes only**. The authors are not responsible for any misuse of this software. Use only on systems you own or have explicit permission to test.

---

<div align="center">

**Created by HUTAOSHUSBAND**
<br/>
All Rights Reserved.

[WallbangBros.com](https://wallbangbros.com) • [FireflyProtector.xyz](https://fireflyprotector.xyz)

</div>
