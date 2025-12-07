import scapy.all as scapy
import socket
import subprocess
import re
import sys
import os

def scan_nmap(target_subnet):
    clients_list = []
    try:
        # Run nmap -sP (Ping Scan)
        # We assume nmap is in the system PATH
        cmd = ['nmap', '-sP', target_subnet]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()
        
        if process.returncode != 0:
            print(f"Nmap error: {err.decode('utf-8', errors='ignore')}")
            return []

        output = out.decode('utf-8', errors='ignore')
        
        # Split output into blocks for each host
        # Nmap output typically separates hosts by blank lines or "Nmap scan report for"
        
        # We can iterate line by line to build state
        lines = output.splitlines()
        current_client = {}
        
        for line in lines:
            line = line.strip()
            if line.startswith("Nmap scan report for"):
                # Save previous client if valid
                if current_client and 'ip' in current_client and 'mac' in current_client:
                    clients_list.append(current_client)
                
                current_client = {"ip": "", "mac": "", "hostname": "Unknown"}
                
                # Parse IP and potential hostname
                # Format 1: Nmap scan report for 192.168.1.1
                # Format 2: Nmap scan report for MyHost (192.168.1.10)
                parts = line.replace("Nmap scan report for ", "").split()
                if len(parts) == 1:
                    current_client['ip'] = parts[0]
                elif len(parts) >= 2:
                    # Check if last part is IP in parens
                    if parts[-1].startswith('(') and parts[-1].endswith(')'):
                        current_client['ip'] = parts[-1].strip('()')
                        current_client['hostname'] = " ".join(parts[:-1])
                    else:
                         current_client['ip'] = parts[0] # Fallback

            elif line.startswith("MAC Address:"):
                # Format: MAC Address: 5C:60:BA:70:79:F8 (HP)
                # Regex to extract MAC and Vendor
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
                     # Try just MAC if no vendor
                     match_mac = re.search(r'MAC Address: ([0-9A-Fa-f:]+)', line)
                     if match_mac:
                         current_client['mac'] = match_mac.group(1)

        # Append the last client
        if current_client and 'ip' in current_client and 'mac' in current_client:
            clients_list.append(current_client)
            
        return clients_list
        
    except FileNotFoundError:
        print("Nmap not found. Please install nmap.")
        return []
    except Exception as e:
        print(f"An error occurred during nmap scan: {e}")
        return []

def scan_scapy(ip):
    print("Using Scapy fallback...")
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    
    try:
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    except Exception as e:
        print(f"Scapy error: {e}")
        return []

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc, "hostname": "Unknown"}
        try:
            hostname = socket.gethostbyaddr(element[1].psrc)[0]
            client_dict["hostname"] = hostname
        except:
            pass
        clients_list.append(client_dict)
    return clients_list

def scan(ip):
    # Try to use nmap first as it gives better vendor info
    # Check if nmap is callable
    try:
        subprocess.check_call(['nmap', '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return scan_nmap(ip)
    except (FileNotFoundError, subprocess.CalledProcessError):
        return scan_scapy(ip)
