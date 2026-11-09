# ARP Sniffer & Spoofing Detector

A network security tool built with **Python 3**, **Scapy**, and **Tkinter** to capture ARP traffic in real-time, detect ARP cache poisoning (Man-in-the-Middle) attacks, and simulate rogue ARP frame injection.

---

## Project Structure

- **`cli_detector.py`**: **Unified Phase 1 CLI Network Sniffer & Anomaly Detector**. Features real-time ANSI color-coded logging, ARP spoofing detection, sliding-window TCP port scan detection, and plaintext credential harvesting (HTTP Basic, POST, FTP, Telnet).
- **`gui.py`**: Graphical user interface version with interactive device tables, security alerts, and full attack simulation lab.
- **`arp_detector.py`**: Standalone ARP detection module.
- **`simulate_spoof.py`**: Rogue ARP frame injector (op=2 ARP reply) to simulate ARP spoofing attacks.
- **`test_all_detectors.py`**: Comprehensive automated verification suite testing ARP spoofing, port scans, and credential interception.
- **`test_detector.py`**: Standalone in-memory unit test for ARP spoofing.
- **`test_sniff.py`**: Quick packet capture sanity check.

---

## How to Run

### 1. CLI Network Sniffer & Anomaly Detector
```powershell
.\sniffer_project\.venv\Scripts\python.exe sniffer_project\cli_detector.py
```
*(Optional arguments: `-i <interface>`, `--threshold 20`, `--window 5.0`)*

### 2. Comprehensive Test Suite
```powershell
.\sniffer_project\.venv\Scripts\python.exe sniffer_project\test_all_detectors.py
```

### 3. Graphical Interface (GUI)
```powershell
.\sniffer_project\.venv\Scripts\python.exe sniffer_project\gui.py
```

### GUI Features

1. **Top Dashboard**:
   - Live metrics: Total packets, ARP frames, active hosts cached, and security alerts.
   - Interface selector (automatically detects network cards like Wi-Fi, Ethernet, and Loopback).
   - BPF Filter configuration (defaults to `arp`).

2. **Control Ribbon**:
   - `▶ Start Sniffer`: Begins asynchronous sniffing in a background thread without freezing the UI.
   - `⏹ Stop Sniffer`: Gracefully halts packet capture.
   - `🧹 Clear`: Resets counters and logs.
   - `💾 Export Report`: Saves a timestamped JSON or Text security incident report.

3. **Tabs**:
   - **🌐 ARP Table & Devices**: Live view of all learned IP and physical MAC mappings, packet counters, and security statuses.
   - **🚨 Security Alerts**: Displays detected ARP spoofing incidents with target IP, original MAC, attacker MAC, and remediation recommendations.
   - **📡 Packet Stream**: Real-time scrolling packet log with auto-scroll and buffer limits.
   - **🧪 Simulation & Lab**:
     - *Live Injection*: Transmit rogue ARP frames using `sendp`.
     - *In-Memory Verification*: Instant test of legitimate vs. conflicting MAC packets without requiring raw socket privileges.

