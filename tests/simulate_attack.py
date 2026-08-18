"""
Advanced Attack Simulation Suite for AegisXDR-Enterprise.
Simulates MITRE ATT&CK adversary tactics:
1. Process Hollowing
2. Token Impersonation
3. Named Pipe Creation (CobaltStrike / PsExec)
4. Registry Run Key Persistence
5. Scheduled Task Persistence
"""

import os
import sys
import time
import json
import logging
import requests
from typing import Dict, Any

# Ensure parent path imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agent.agent_client import AegisAgentClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("AttackSimulator")

class AttackSimulator:
    """
    Generates synthetic adversary attack telemetry for validation of SIEM correlation rules,
    Process Tree detection engines, and SOAR mitigation response workflows.
    """
    def __init__(self, server_url: str = "http://127.0.0.1:8000/api/v1/telemetry"):
        self.server_url = server_url
        self.client = AegisAgentClient(server_url=server_url)

    def execute_all_scenarios(self):
        """Runs all 5 advanced adversary attack simulations."""
        logger.info("==========================================================")
        logger.info("  AegisXDR-Enterprise Advanced Attack Simulation Suite   ")
        logger.info("==========================================================")

        self.scenario_1_process_hollowing()
        time.sleep(1)

        self.scenario_2_token_impersonation()
        time.sleep(1)

        self.scenario_3_named_pipe_creation()
        time.sleep(1)

        self.scenario_4_registry_persistence()
        time.sleep(1)

        self.scenario_5_scheduled_task_persistence()
        time.sleep(1)

        logger.info("[+] All 5 Adversary Attack Simulations Transmitted Successfully!")

    def _post_telemetry(self, event: Dict[str, Any]):
        """Transmits simulated telemetry directly to FastAPI Core server."""
        try:
            res = requests.post(self.server_url, json=event, timeout=4)
            if res.status_code == 200:
                data = res.json()
                logger.info(f"[+] Transmitted {event.get('event_type', 'EVENT')} -> Server Ingested (Alerts: {data.get('alerts_generated', 0)})")
            else:
                logger.warning(f"[-] Server returned status {res.status_code}: {res.text}")
        except Exception as e:
            logger.error(f"[-] Simulation transmission error: {e}")

    def scenario_1_process_hollowing(self):
        """1. Process Hollowing: Spawns svchost.exe in suspended state and overwrites memory."""
        logger.info("\n[*] Scenario 1: Process Hollowing Simulation")
        event = {
            "agent_id": "SIM-AGENT-01",
            "hostname": "FINANCE-DC-01",
            "event_type": "PROCESS_CREATION",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "pid": 7120,
            "process_name": "svchost.exe",
            "ppid": 3412,
            "parent_name": "malware_loader.exe",
            "cmdline": "svchost.exe -k netsvcs -p",
            "process_path": "C:\\Windows\\System32\\svchost.exe",
            "user": "NT AUTHORITY\\SYSTEM",
            "encrypted": False
        }
        self._post_telemetry(event)

    def scenario_2_token_impersonation(self):
        """2. Token Impersonation: Elevates privileges from low service to SYSTEM via incognito/runas."""
        logger.info("\n[*] Scenario 2: Token Impersonation Simulation")
        event = {
            "agent_id": "SIM-AGENT-01",
            "hostname": "FINANCE-DC-01",
            "event_type": "PROCESS_CREATION",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "pid": 8940,
            "process_name": "cmd.exe",
            "ppid": 5120,
            "parent_name": "incognito.exe",
            "cmdline": "cmd.exe /c whoami /all && net user backdoor P@ss123 /add",
            "process_path": "C:\\Windows\\System32\\cmd.exe",
            "user": "NT AUTHORITY\\SYSTEM",
            "encrypted": False
        }
        self._post_telemetry(event)

    def scenario_3_named_pipe_creation(self):
        """3. Named Pipe Creation: Simulates CobaltStrike / PsExec pipe initialization."""
        logger.info("\n[*] Scenario 3: Named Pipe Creation (CobaltStrike / PsExec)")
        event = {
            "agent_id": "SIM-AGENT-01",
            "hostname": "FINANCE-DC-01",
            "event_type": "FILE_CREATE",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "pid": 6420,
            "process_name": "rundll32.exe",
            "target_filename": "\\\\.\\pipe\\msagent_12",
            "cmdline": "rundll32.exe C:\\Windows\\Temp\\beacon.dll,Start",
            "user": "NT AUTHORITY\\SYSTEM",
            "encrypted": False
        }
        self._post_telemetry(event)

    def scenario_4_registry_persistence(self):
        """4. Registry Run Keys Persistence: Modifies HKCU Run key for autostart persistence."""
        logger.info("\n[*] Scenario 4: Registry Run Keys Persistence Simulation")
        event = {
            "agent_id": "SIM-AGENT-01",
            "hostname": "FINANCE-DC-01",
            "event_type": "PROCESS_CREATION",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "pid": 9120,
            "process_name": "reg.exe",
            "ppid": 4812,
            "parent_name": "powershell.exe",
            "cmdline": "reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v AegisUpdater /t REG_SZ /d \"C:\\Windows\\Temp\\update.exe\" /f",
            "process_path": "C:\\Windows\\System32\\reg.exe",
            "user": "FINANCE\\admin",
            "encrypted": False
        }
        self._post_telemetry(event)

    def scenario_5_scheduled_task_persistence(self):
        """5. Scheduled Task Persistence: Creates hidden scheduled task running encoded PowerShell."""
        logger.info("\n[*] Scenario 5: Scheduled Task Persistence Simulation")
        event = {
            "agent_id": "SIM-AGENT-01",
            "hostname": "FINANCE-DC-01",
            "event_type": "PROCESS_CREATION",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "pid": 9840,
            "process_name": "schtasks.exe",
            "ppid": 2104,
            "parent_name": "cmd.exe",
            "cmdline": "schtasks.exe /create /tn \"WindowsSystemUpdate\" /tr \"powershell.exe -w hidden -enc SQBFAFgA...\" /sc daily /st 09:00",
            "process_path": "C:\\Windows\\System32\\schtasks.exe",
            "user": "FINANCE\\admin",
            "encrypted": False
        }
        self._post_telemetry(event)

if __name__ == "__main__":
    simulator = AttackSimulator()
    simulator.execute_all_scenarios()
