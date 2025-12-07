import socket
import subprocess
import re
import sys
import os

# Determine base path for tools
if getattr(sys, 'frozen', False):
    # If run as exe, use the directory of the executable
    BASE_DIR = os.path.dirname(sys.executable)
else:
    # If run as script, use the current working directory or script directory
    BASE_DIR = os.getcwd()

# Path to nmap executable
NMAP_PATH = os.path.join(BASE_DIR, 'tools', 'nmap', 'nmap.exe')

def scan_nmap(target_subnet):
    clients_list = []
    try:
        # Run nmap -sP (Ping Scan)
        if not os.path.exists(NMAP_PATH):
             print(f"Nmap not found at {NMAP_PATH}")
             return []

        print(f"[DEBUG] Executing nmap scan on: {target_subnet}")

        # -sn: Ping Scan - disable port scan (same as -sP in older versions, but cleaner)
        # -PE: ICMP Echo
        cmd = [NMAP_PATH, '-sn', target_subnet]
        # Hide window on Windows
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=startupinfo)
        out, err = process.communicate()
        
        if process.returncode != 0:
            print(f"Nmap error: {err.decode('utf-8', errors='ignore')}")
            return []

        output = out.decode('utf-8', errors='ignore')
        
        lines = output.splitlines()
        current_client = {}
        
        for line in lines:
            line = line.strip()
            if line.startswith("Nmap scan report for"):
                if current_client and 'ip' in current_client:
                     # If we have a previous client with at least an IP, append it.
                     # Note: Sometimes MAC is missing if we scan localhost or similar, but usually present for LAN.
                     clients_list.append(current_client)
                
                current_client = {"ip": "", "mac": "", "hostname": "Unknown"}
                
                parts = line.replace("Nmap scan report for ", "").split()
                if len(parts) == 1:
                    current_client['ip'] = parts[0]
                elif len(parts) >= 2:
                    if parts[-1].startswith('(') and parts[-1].endswith(')'):
                        current_client['ip'] = parts[-1].strip('()')
                        current_client['hostname'] = " ".join(parts[:-1])
                    else:
                        current_client['ip'] = parts[0]

            elif line.startswith("MAC Address:"):
                match = re.search(r'MAC Address: ([0-9A-Fa-f:]+)\s*\((.*)\)', line)
                if match:
                    current_client['mac'] = match.group(1)
                    vendor = match.group(2)
                    if vendor != "Unknown":
                        if current_client['hostname'] == "Unknown":
                            current_client['hostname'] = vendor
                        else:
                            current_client['hostname'] += f" ({vendor})"
                else:
                     match_mac = re.search(r'MAC Address: ([0-9A-Fa-f:]+)', line)
                     if match_mac:
                         current_client['mac'] = match_mac.group(1)

        if current_client and 'ip' in current_client:
            clients_list.append(current_client)
            
        return clients_list
        
    except Exception as e:
        print(f"An error occurred during nmap scan: {e}")
        return []

def scan(subnet):
    return scan_nmap(subnet)
