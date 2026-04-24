# 🌌 Galaxy Monitor - Network Traffic Analysis Platform

A professional network traffic monitoring tool with a modern web interface. Capture and analyze network packets in real-time, identify services, and monitor network activity.

## ✨ Features

- 📡 **Real-time packet capture** (TCP, UDP, ICMP)
- 🔍 **Service detection** (HTTP, HTTPS, DNS, SSH, MySQL, PostgreSQL, FTP)
- 📊 **Live traffic statistics** (packet counts, sizes, protocols)
- 🎨 **Modern dark/light theme** interface
- 📁 **CSV import/export** support
- 📱 **Multiple interface support** (Wi-Fi, Ethernet, Bluetooth, Cellular, VPN)

## 🏗️ Architecture
Frontend (Vercel) ←→ Backend (Local)
https://galaxy-packet-sniffer.vercel.app ←→ http://localhost:8765

text

## 📋 Prerequisites

| Requirement | Version | Command |
|-------------|---------|---------|
| Windows OS | 10/11 | `winver` |
| Python | 3.8+ | `python --version` |
| Npcap | 1.60+ | Install from npcap.com |
| Git | Latest | `git --version` |

## 🚀 Quick Start

### Step 1: Install Npcap

1. Download from [https://npcap.com](https://npcap.com)
2. Run installer as **Administrator**
3. **CHECK** these options:
   - ✅ `Install Npcap in WinPcap API-compatible Mode`
   - ✅ `Support raw 802.11 traffic (and monitor mode)`
4. Restart your computer

### Step 2: Clone Repository

```bash
git clone https://github.com/Javeriaakram-07/Galaxy-packet-sniffer.git
cd Galaxy-packet-sniffer
Step 3: Install Python Dependencies
bash
cd Galaxy_backend
pip install flask flask-cors scapy
Step 4: Run Backend (as Administrator)
Open Terminal as Administrator (Right-click → Run as Administrator):

bash
cd "C:\Users\User\CS\4th sem\CN Project\Galaxy_backend"
python sniffer.py
Expected output:

text
==================================================
  NetMon Backend - Complete Edition
==================================================
  Server: http://localhost:8765
==================================================
 * Running on http://127.0.0.1:8765
Step 5: Access Frontend
Open browser and go to:

text
https://galaxy-packet-sniffer.vercel.app
🔧 Backend API Endpoints
Endpoint	Method	Description
/api/devices	GET	List network interfaces
/api/start?dev=DEVICE	GET	Start capture
/api/stop	GET	Stop capture
/api/stats	GET	Traffic statistics
/api/packets	GET	Captured packets
/api/clear	GET	Clear history
📸 Usage Guide
Select Interface - Choose Wi-Fi, Ethernet, Bluetooth, Cellular, or VPN

Click Start - Begin packet capture

View Statistics - Monitor real-time metrics

Filter Packets - By protocol, source IP, or destination IP

Load Demo Data - Preview without backend

🐛 Troubleshooting
"Backend unreachable"
bash
# Check if backend is running
curl http://localhost:8765/api/devices

# Start backend as Administrator
cd Galaxy_backend
python sniffer.py
"Interface not found"
Run backend as Administrator

Reinstall Npcap with WinPcap API compatibility

Restart computer

Empty device list
bash
# Test Scapy detection
python -c "from scapy.all import *; from scapy.arch.windows import get_windows_if_list; print([i.get('description') for i in get_windows_if_list()])"
Port 8765 already in use
bash
# Find process using port
netstat -ano | findstr :8765

# Kill process (replace PID)
taskkill /PID 12345 /F
⚠️ Important Notes
Administrator privileges required for packet capture

Npcap must be installed with WinPcap API compatibility

Local backend only - cloud deployment not supported for capture

Restart computer after Npcap installation

🔄 Quick Commands
bash
# Start Python Backend (as Administrator)
cd Galaxy_backend && python sniffer.py

# Install Dependencies
pip install flask flask-cors scapy

# Test Backend
curl http://localhost:8765/api/devices

# Compile C++ Backend
g++ sniffer.cpp -o sniffer.exe -I"C:\Users\User\Downloads\npcap-sdk-1.16\Include" -L"C:\Users\User\Downloads\npcap-sdk-1.16\Lib\x64" -lwpcap -lPacket -lws2_32 -std=c++17 -O2
📁 Project Structure
text
Galaxy-packet-sniffer/
├── Galaxy_backend/
│   ├── sniffer.py          # Python backend
│   ├── sniffer.cpp         # C++ backend
│   └── requirements.txt    # Dependencies
├── Galaxy_frontend/
│   └── index.html          # Web interface
└── vercel.json             # Vercel config
📞 Links
Frontend: https://galaxy-packet-sniffer.vercel.app

Backend (local): http://localhost:8765

GitHub: https://github.com/Javeriaakram-07/Galaxy-packet-sniffer

👨‍💻 Author
Javeria Akram

⭐ Star this repository if you find it useful!