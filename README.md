# 🦈 Mini Wireshark Enterprise (PowerShell Packet Analyzer)

<img width="256" height="256" alt="app" src="https://github.com/user-attachments/assets/17dc76dd-8315-4adc-9194-2e857514f81d" />



A high-performance, multi-threaded network packet capture and analysis tool built entirely using PowerShell and Windows Forms (WinForms). Designed to provide a lightweight, dependency-free GUI alternative for real-time network troubleshooting and packet inspection on Windows.

---

## ✨ Key Features

* **Background Capture Engine:** Uses isolated PowerShell Runspaces and Raw Sockets (`ReceiveAll`) to capture live network traffic without freezing or lagging the UI.
* **High-Performance Virtual ListView (`VirtualMode`):** Capable of rendering 10,000+ packets smoothly with zero memory bloating or lag using direct memory arrays.
* **Thread-Safe Architecture:** Implements `ConcurrentQueue` and synchronized hashtables to prevent thread race conditions between the packet capture engine and the UI consumer.
* **Background Pre-Filtering:** Filters keywords dynamically inside the background runspace before items reach the UI queue, minimizing workload.
* **Deep Protocol Inspection:** Decodes standard IP headers, mapping protocols including TCP, UDP, ICMP, HTTP, HTTPS, and DNS.  
* **Hex & ASCII Payload Dump:** Generates detailed packet footprints with side-by-side Hexadecimal and ASCII previews.
* **Ring Buffer Protection:** Automatically manages memory by capping maximum stored items (default: 10,000 packets).
* **CSV Export & Import:** Save captured sessions along with full payload details for offline forensics or share them easily with teammates.

---

## 🛠️ System Requirements  

* **OS:** Windows 10 / 11 (64-bit recommended) or Windows Server.  
* **Privileges:** Must be run with **Administrator privileges** (required for binding raw sockets/network interfaces).
* **PowerShell:** Version 5.1 or higher.  

---

## 🚀 Getting Started  

1. Clone or download this repository.
2. Open **PowerShell as Administrator**.  
3. Navigate to the script directory and execute the script:
   ```powershell
   .\MiniWireshark.ps1
