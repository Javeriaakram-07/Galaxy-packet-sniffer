markdown
# 🌌 Galaxy Monitor - Network Traffic Analysis Platform

A professional network traffic monitoring tool with a modern web interface. Capture and analyze network packets in real-time, identify services, and monitor network activity.

## ✨ Features

- 📡 **Real-time packet capture** (TCP, UDP, ICMP)
- 🔍 **Service detection** (HTTP, HTTPS, DNS, SSH, MySQL, etc.)
- 📊 **Live traffic statistics** (packet counts, sizes, protocols)
- 🎨 **Modern dark/light theme** interface
- 📁 **CSV import/export** support
- 📱 **Cellular, VPN, Bluetooth, Ethernet, Wi-Fi** interface selection
- 🚀 **Cloud-ready frontend** + local backend

## 🏗️ Architecture
Frontend (Vercel) ←→ Backend (Local/Cloud)
https://galaxy-packet-sniffer.vercel.app ←→ http://localhost:8765

text

## 📋 Prerequisites

| Requirement | Version | Check Command |
|-------------|---------|----------------|
| Python | 3.8+ | `python --version` |
| pip | Latest | `pip --version` |
| Npcap (Windows) | 1.60+ | Installed via installer |
| Git | Latest | `git --version` |

## 🚀 Quick Start

### Option 1: Python Backend (Recommended)

#### Step 1: Install Npcap (Windows Only)

1. Download from [https://npcap.com](https://npcap.com)
2. **Run installer as Administrator**
3. **IMPORTANT - Check these options:**
   - ✅ `Install Npcap in WinPcap API‑compatible Mode`
   - ✅ `Support raw 802.11 traffic (and monitor mode)`
4. Complete installation
5. **Restart your computer**

#### Step 2: Clone & Navigate

```bash
git clone https://github.com/Javeriaakram-07/Galaxy-packet-sniffer.git
cd Galaxy-packet-sniffer
Step 3: Install Python Dependencies
bash
cd Galaxy_backend
pip install flask flask-cors scapy
Or use requirements.txt:

bash
pip install -r requirements.txt
Step 4: Run the Backend
⚠️ IMPORTANT: Run as Administrator (required for packet capture)

Windows (PowerShell/CMD as Admin):

bash
cd Galaxy_backend
python sniffer.py
Expected output:

text
==================================================
  NetMon Backend - Complete Edition
==================================================
  Server: http://localhost:8765
  Features:
    - 5 Device Types: Wi-Fi, Ethernet, Bluetooth, Cellular, VPN
    - All Services: HTTP, HTTPS, DNS, SSH, FTP, MySQL, etc.
==================================================
 * Running on http://127.0.0.1:8765
Step 5: Access the Frontend
Open your browser and go to:

text
https://galaxy-packet-sniffer.vercel.app
Option 2: C++ Backend (Original)
Step 1: Install Npcap SDK
Download Npcap SDK from https://npcap.com

Extract to C:\Users\User\Downloads\npcap-sdk-1.16

Step 2: Compile
bash
cd Galaxy_backend
g++ sniffer.cpp -o sniffer.exe -I"C:\Users\User\Downloads\npcap-sdk-1.16\Include" -L"C:\Users\User\Downloads\npcap-sdk-1.16\Lib\x64" -lwpcap -lPacket -lws2_32 -std=c++17 -O2
Step 3: Run as Administrator
bash
sniffer.exe
🔧 Configuration
Backend API Endpoints
Endpoint	Method	Description
/api/devices	GET	List available network interfaces
/api/start?dev=DEVICE	GET	Start packet capture on device
/api/stop	GET	Stop packet capture
/api/stats	GET	Get traffic statistics
/api/packets	GET	Get captured packets
/api/clear	GET	Clear packet history
Frontend API URL
If running backend on different port/host, update in Galaxy_frontend/index.html:

javascript
const API = 'http://localhost:8765';  // Change this
📸 Usage Guide
1. Select Network Interface
Choose from detected interfaces:

📡 Wi-Fi - Wireless network traffic

🔌 Ethernet - Wired network traffic

🔵 Bluetooth - Bluetooth traffic

📱 Cellular - USB tethering / 4G/5G

🔒 VPN - VPN tunnel traffic

2. Start Monitoring
Click ▶ Start to begin packet capture

3. View Statistics
Real-time metrics show:

Total packets captured

Protocol breakdown (TCP/UDP/ICMP)

Average packet size

4. Filter Packets
Filter by:

Protocol (TCP/UDP/ICMP)

Source IP address

Destination IP address

5. Load Demo Data
Click ⚡ Load Built-in Demo Data to preview without backend

🐛 Troubleshooting
"Backend unreachable" error
Solution:

bash
# Check if backend is running
curl http://localhost:8765/api/devices

# If not running, start it:
cd Galaxy_backend
python sniffer.py
"Interface not found" error
Solution:

Run backend as Administrator

Reinstall Npcap with WinPcap API compatibility

Restart your computer

Empty device list
Solution:

python
# Test Scapy detection
python -c "from scapy.all import *; from scapy.arch.windows import get_windows_if_list; print([i.get('description') for i in get_windows_if_list()])"
Port 8765 already in use
Solution:

bash
# Find process using port 8765
netstat -ano | findstr :8765
# Kill the process (replace PID)
taskkill /PID <PID> /F
🌐 Deployment
Frontend (Vercel)
The frontend is already deployed at:

text
https://galaxy-packet-sniffer.vercel.app
To redeploy:

bash
npm install -g vercel
vercel --prod
Backend (Local Only)
Packet capture requires local execution due to network access limitations. Cloud deployment is not supported for packet capture.

📁 Project Structure
text
Galaxy-packet-sniffer/
├── Galaxy_backend/
│   ├── sniffer.py          # Python backend
│   ├── sniffer.cpp         # C++ backend
│   └── requirements.txt    # Python dependencies
├── Galaxy_frontend/
│   └── index.html          # Web interface
├── vercel.json             # Vercel deployment config
└── README.md               # This file
🛠️ Tech Stack
Component	Technology
Frontend	HTML5, CSS3, JavaScript
Backend (Python)	Flask, Flask-CORS, Scapy
Backend (C++)	WinPcap/Npcap, Winsock2
Deployment	Vercel (frontend), Local (backend)
Packet Capture	Npcap / libpcap
⚠️ Important Notes
Administrator privileges required for packet capture

Npcap must be installed with WinPcap API compatibility

Local backend only - cloud deployment not supported for capture

Firewall exceptions may be needed for port 8765

📞 Support
Issues: GitHub Issues

Frontend: https://galaxy-packet-sniffer.vercel.app

Backend API: http://localhost:8765

📄 License
This project is for educational and portfolio purposes.

👨‍💻 Author
Javeria Akram

🔄 Quick Commands Reference
bash
# Start Python Backend (as Administrator)
cd Galaxy_backend && python sniffer.py

# Install Python Dependencies
pip install flask flask-cors scapy

# Test Backend
curl http://localhost:8765/api/devices

# Compile C++ Backend
g++ sniffer.cpp -o sniffer.exe -I"C:\Users\User\Downloads\npcap-sdk-1.16\Include" -L"C:\Users\User\Downloads\npcap-sdk-1.16\Lib\x64" -lwpcap -lPacket -lws2_32 -std=c++17 -O2

# Deploy Frontend to Vercel
vercel --prod
⭐ Star this repository if you find it useful!


