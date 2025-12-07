import subprocess
import re
import os
import sys

ARPSPOOF_PATH = os.path.join(os.getcwd(), 'tools', 'arpspoof.exe')

def test_parsing():
    if not os.path.exists(ARPSPOOF_PATH):
        print(f"Error: {ARPSPOOF_PATH} not found")
        return

    print(f"Running {ARPSPOOF_PATH} --list")
    try:
        # Try capturing as raw bytes first
        cmd = [ARPSPOOF_PATH, "--list"]
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        
        # Use run instead of check_output to handle non-zero exit code
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, startupinfo=startupinfo)
        
        # Combine stdout and stderr because arpspoof might print to stderr? 
        # But previous logs showed it on stdout. 
        # However, check_output raises error on exit code 1.
        raw_output = result.stdout + result.stderr
        
        print(f"Exit code: {result.returncode}")
        print(f"Raw output len: {len(raw_output)}")
        
        # Try decoding with mbcs (Windows default ANSI) or utf-8
        try:
            output = raw_output.decode('mbcs')
            print("Decoded with mbcs")
        except:
            output = raw_output.decode('utf-8', errors='ignore')
            print("Decoded with utf-8 (fallback)")
            
        print("-" * 20)
        print(output)
        print("-" * 20)
        
        interfaces = []
        lines = output.splitlines()
        current_iface = {}
        
        for line in lines:
            line = line.strip()
            if not line: continue
            
            print(f"Processing line: {line}")
            
            # Match line 1: Index. Name Description
            # Regex: ^(\d+)\.\s+(\S+)\s+(.*)$
            match_header = re.match(r'^(\d+)\.\s+(\S+)\s+(.*)$', line)
            if match_header:
                print("  -> Matched Header")
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
                if match_ip:
                    print("  -> Matched IP")
                    if current_iface:
                        current_iface['ip'] = match_ip.group(1)
                        current_iface['gateway'] = match_ip.group(3)
                else:
                    print("  -> No match")

        if current_iface:
            interfaces.append(current_iface)
            
        print(f"\nFound {len(interfaces)} interfaces:")
        for i in interfaces:
            print(i)

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_parsing()
