from flask import Flask, jsonify, request
from flask_cors import CORS
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from threading import Thread, Lock
from datetime import datetime
from collections import deque
import sys
import time

# ==================== Configuration ====================
MAX_PACKETS = 5000
PORT = 8765

# ==================== Global State ====================
packets = deque(maxlen=MAX_PACKETS)
packets_lock = Lock()
capturing = False
current_device = None

# ==================== Complete Service Mapping (All Ports) ====================
def port_to_service(port):
    services = {
        # Web
        80: "HTTP",
        443: "HTTPS",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
        8000: "HTTP-Alt",
        3000: "React/Node",
        5000: "Flask",
        
        # Email
        25: "SMTP",
        465: "SMTPS",
        587: "SMTP",
        110: "POP3",
        995: "POP3S",
        143: "IMAP",
        993: "IMAPS",
        
        # File Transfer
        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        69: "TFTP",
        
        # Database
        3306: "MySQL",
        5432: "PostgreSQL",
        1433: "MSSQL",
        27017: "MongoDB",
        6379: "Redis",
        1521: "OracleDB",
        
        # DNS & DHCP
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        
        # Remote Access
        3389: "RDP",
        5900: "VNC",
        5800: "VNC",
        22: "SSH",
        23: "Telnet",
        
        # VPN & Tunneling
        500: "IKE/VPN",
        4500: "IPSec",
        1194: "OpenVPN",
        1723: "PPTP",
        
        # Messaging & Collaboration
        5222: "XMPP",
        5228: "GCM/Android",
        1863: "MSNP",
        5050: "XMPP",
        194: "IRC",
        6667: "IRC",
        
        # Network Services
        123: "NTP",
        161: "SNMP",
        162: "SNMP-Trap",
        389: "LDAP",
        636: "LDAPS",
        445: "SMB",
        137: "NetBIOS",
        138: "NetBIOS",
        139: "NetBIOS",
        135: "RPC",
        
        # Media Streaming
        1935: "RTMP",
        554: "RTSP",
        1755: "MMS",
        
        # Gaming
        27015: "Steam",
        25565: "Minecraft",
        3074: "Xbox Live",
        3659: "Apple",
        
        # Other
        5353: "mDNS",
        1900: "SSDP",
        1434: "SQL-Server",
        5432: "PostgreSQL",
        11211: "Memcached",
    }
    
    # Try exact match first
    if port in services:
        return services[port]
    
    # Try ranges for common services
    if 8000 <= port <= 9000:
        return "Web-Alt"
    elif 50000 <= port <= 60000:
        return "P2P/Dynamic"
    elif port > 10000:
        return "HighPort"
    
    return "Unknown"

# ==================== Packet Handler ====================
def packet_handler(packet):
    if not capturing:
        return
    
    timestamp = datetime.now().strftime("%H:%M:%S")
    
    if IP not in packet:
        return
    
    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    size = len(packet)
    
    protocol = "OTHER"
    src_port = 0
    dst_port = 0
    service = "N/A"
    
    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        # Check destination port first, then source port
        service = port_to_service(dst_port)
        if service == "Unknown" and src_port < 10000:
            service = port_to_service(src_port)
            
    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        service = port_to_service(dst_port)
        if service == "Unknown" and src_port < 10000:
            service = port_to_service(src_port)
            
    elif ICMP in packet:
        protocol = "ICMP"
        service = "ICMP"
    
    packet_data = {
        'time': timestamp,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'protocol': protocol,
        'src_port': src_port,
        'dst_port': dst_port,
        'size': size,
        'service': service
    }
    
    with packets_lock:
        packets.append(packet_data)
        
        # Keep only last MAX_PACKETS
        while len(packets) > MAX_PACKETS:
            packets.popleft()

def capture_loop():
    global capturing
    print(f"[INFO] Capturing on: {current_device}")
    
    try:
        sniff(iface=current_device, prn=packet_handler, store=False, 
              stop_filter=lambda x: not capturing)
    except Exception as e:
        print(f"[ERROR] Capture failed: {e}")
        capturing = False

# ==================== Flask API ====================
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Handle preflight requests
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    return response

@app.route('/api/devices', methods=['GET', 'OPTIONS'])
def get_devices():
    if request.method == 'OPTIONS':
        return '', 200
    
    devices = []
    
    # Track which types we've found
    found_wifi = False
    found_ethernet = False
    found_bluetooth = False
    found_cellular = False
    found_vpn = False
    
    # Real device names to match
    real_devices = {
        'wifi': ['wi-fi', 'wifi', 'wireless', 'realtek', 'broadcom'],
        'ethernet': ['ethernet', 'gigabit', 'intel ethernet', 'pcie'],
        'bluetooth': ['bluetooth'],
        'cellular': ['remote ndis', 'mobile broadband', 'cellular', 'wwan'],
        'vpn': ['tap', 'openvpn', 'vpn', 'tunnel', 'wireguard', 'nordvpn', 'expressvpn']
    }
    
    if sys.platform == "win32":
        try:
            from scapy.arch.windows import get_windows_if_list
            for iface in get_windows_if_list():
                name = iface.get('name', '')
                desc = iface.get('description', '')
                desc_lower = desc.lower()
                
                # Skip useless virtual adapters
                skip_keywords = ['miniport', 'filter', 'npcap', 'kernel debug', 'ip-https', '6to4', 
                                'microsoft wi-fi direct', 'wan miniport', 'loopback', 'qos', 'wfp', 
                                'lightweight', 'remote ndis filter']
                
                should_skip = any(v in desc_lower for v in skip_keywords)
                if should_skip:
                    continue
                
                # Check for VPN first
                if not found_vpn and any(v in desc_lower for v in real_devices['vpn']):
                    devices.append({'name': name, 'desc': ' VPN'})
                    found_vpn = True
                
                # Check for Wi-Fi
                elif not found_wifi and any(w in desc_lower for w in real_devices['wifi']):
                    devices.append({'name': name, 'desc': ' Wi-Fi'})
                    found_wifi = True
                   # Check for Cellular (only if REAL device exists)
                elif not found_cellular and any(c in desc_lower for c in real_devices['cellular']):
                    devices.append({'name': name, 'desc': ' Cellular'})
                    found_cellular = True
                # Check for Ethernet
                elif not found_ethernet and any(e in desc_lower for e in real_devices['ethernet']):
                    devices.append({'name': name, 'desc': ' Ethernet'})
                    found_ethernet = True
                
                # Check for Bluetooth
                elif not found_bluetooth and 'bluetooth' in desc_lower:
                    devices.append({'name': name, 'desc': ' Bluetooth'})
                    found_bluetooth = True
                
             
                    
        except Exception as e:
            print(f"[ERROR] Getting devices: {e}")
    
    # Add placeholders for missing types — name='' means not available on this machine
    if not found_vpn:
        devices.append({'name': '', 'desc': ' VPN (not detected)'})
    if not found_wifi:
        devices.append({'name': '', 'desc': ' Wi-Fi (not detected)'})
    if not found_ethernet:
        devices.append({'name': '', 'desc': ' Ethernet (not detected)'})
    if not found_bluetooth:
        devices.append({'name': '', 'desc': ' Bluetooth (not detected)'})
    # Cellular only shows when real device exists
    
    return jsonify(devices[:5])

@app.route('/api/stats', methods=['GET', 'OPTIONS'])
def get_stats():
    if request.method == 'OPTIONS':
        return '', 200
    
    with packets_lock:
        total = len(packets)
        tcp = sum(1 for p in packets if p['protocol'] == "TCP")
        udp = sum(1 for p in packets if p['protocol'] == "UDP")
        icmp = sum(1 for p in packets if p['protocol'] == "ICMP")
        other = total - tcp - udp - icmp
        total_size = sum(p['size'] for p in packets)
        avg_size = total_size // total if total > 0 else 0
        
        return jsonify({
            'total': total,
            'tcp': tcp,
            'udp': udp,
            'icmp': icmp,
            'other': other,
            'avg_size': avg_size,
            'running': capturing
        })

@app.route('/api/packets', methods=['GET', 'OPTIONS'])
def get_packets():
    if request.method == 'OPTIONS':
        return '', 200
    
    with packets_lock:
        return jsonify(list(packets))

@app.route('/api/start', methods=['GET', 'POST', 'OPTIONS'])
def start_capture():
    if request.method == 'OPTIONS':
        return '', 200
    
    global capturing, current_device
    
    if capturing:
        return jsonify({'ok': False, 'msg': 'Already running'})
    
    device = request.args.get('dev', '')
    if not device:
        device = request.json.get('dev', '') if request.is_json else ''
    
   
    
    current_device = device
    capturing = True
    
    with packets_lock:
        packets.clear()
    
    thread = Thread(target=capture_loop)
    thread.daemon = True
    thread.start()
    
    return jsonify({'ok': True, 'msg': f'Started on {device}'})

@app.route('/api/stop', methods=['GET', 'POST', 'OPTIONS'])
def stop_capture():
    if request.method == 'OPTIONS':
        return '', 200
    
    global capturing
    capturing = False
    time.sleep(0.5)
    return jsonify({'ok': True, 'msg': 'Stopped'})

@app.route('/api/clear', methods=['GET', 'POST', 'OPTIONS'])
def clear_packets():
    if request.method == 'OPTIONS':
        return '', 200
    
    with packets_lock:
        packets.clear()
    return jsonify({'ok': True})

if __name__ == '__main__':
    print("\n" + "="*55)
    print("  Galaxy Backend - Complete Edition")
    print("="*55)
    print(f"  Server: http://localhost:{PORT}")
    print("  Features:")
    print("    - 4 Device Types: Wi-Fi, Ethernet, Bluetooth, Cellular")
    print("    - All Services: HTTP, HTTPS, DNS, SSH, FTP, MySQL, etc.")
    print("="*55 + "\n")
    
    app.run(host='0.0.0.0', port=PORT, debug=False)