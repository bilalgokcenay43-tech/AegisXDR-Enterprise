"""
Advanced SIGMA & Behavioral Rule Engine for AegisXDR-Enterprise.
Detects LSASS process memory access, anomalous Parent-Child execution chains,
and performs automatic Base64 & UTF-16LE decoding for obfuscated PowerShell commands.
"""

import re
import base64
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("SigmaRulesEngine")

class AdvancedSigmaEngine:
    """
    Advanced SIEM Detection Rule Engine.
    Handles LSASS memory protection (Event ID 10), process tree anomalies, and CLI payload decoding.
    """
    def __init__(self):
        # LSASS Suspicious Access Masks
        self.lsass_suspicious_access = ["0x1010", "0x1f0fff", "0x1410", "0x0010", "0x1400", "0x1000"]
        
        # Suspicious Parent Process Mappings for Shell Spawning
        self.anomalous_parents = {
            "wmiprvse.exe": ["cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe"],
            "rundll32.exe": ["cmd.exe", "powershell.exe", "pwsh.exe"],
            "mshta.exe": ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe"],
            "wscript.exe": ["cmd.exe", "powershell.exe", "cscript.exe"],
            "cscript.exe": ["cmd.exe", "powershell.exe"],
            "winword.exe": ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "bitsadmin.exe"],
            "excel.exe": ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe"],
            "powerpnt.exe": ["cmd.exe", "powershell.exe"],
            "outlook.exe": ["cmd.exe", "powershell.exe"]
        }

    def decode_powershell_payload(self, cmdline: str) -> Optional[str]:
        """
        Detects PowerShell encoded flags (-enc, -encodedcommand, -e, -ec)
        and decodes Base64 UTF-16LE command string back to raw readable script text.
        """
        if not cmdline:
            return None

        # Regex match for -enc, -encodedcommand, -e, -ec followed by base64 string
        pattern = r"(?:-enc|-encodedcommand|-e|-ec)\s+([A-Za-z0-9+/=]+)"
        match = re.search(pattern, cmdline, re.IGNORECASE)
        if match:
            b64_str = match.group(1)
            try:
                decoded_bytes = base64.b64decode(b64_str)
                # Try UTF-16LE decoding (default for PowerShell encoded commands)
                try:
                    decoded_text = decoded_bytes.decode("utf-16le")
                except UnicodeDecodeError:
                    decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
                
                logger.info(f"[Encoded Command Decoder] Decoded Base64 payload: {decoded_text[:80]}...")
                return decoded_text
            except Exception as e:
                logger.warning(f"Failed to decode Base64 command string '{b64_str}': {e}")
                return None
        return None

    def evaluate_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluates a telemetry event against advanced SIGMA rules.
        Returns a list of generated rule alert dictionaries.
        """
        alerts = []
        event_id = event.get("event_id")
        event_type = event.get("event_type", "")
        
        process_name = (event.get("process_name") or "").lower()
        parent_name = (event.get("parent_name") or event.get("source_name") or "").lower()
        cmdline = event.get("cmdline") or ""
        
        # -------------------------------------------------------------
        # Rule 1: LSASS Process Access Rights (Sysmon Event ID 10)
        # -------------------------------------------------------------
        target_name = (event.get("target_name") or "").lower()
        granted_access = (event.get("granted_access") or "").lower()

        if event_id == 10 or event_type == "PROCESS_ACCESS" or target_name == "lsass.exe":
            if target_name == "lsass.exe" and any(mask in granted_access for mask in self.lsass_suspicious_access):
                alerts.append({
                    "rule_id": "SIGMA-LSASS-001",
                    "rule_title": f"Suspicious Access Mask to LSASS.exe ({granted_access})",
                    "severity": "CRITICAL",
                    "base_score": 90,
                    "mitre_tactic": "Credential Access",
                    "mitre_technique": "T1003.001 - LSASS Memory Dumping",
                    "description": (
                        f"Process '{parent_name or process_name}' requested dangerous access rights "
                        f"({granted_access}) to LSASS process memory. Potential Mimikatz / Procdump activity."
                    )
                })

        # -------------------------------------------------------------
        # Rule 2: Suspicious Parent-Child Process Hierarchy
        # -------------------------------------------------------------
        if parent_name in self.anomalous_parents:
            allowed_children = [c.lower() for c in self.anomalous_parents[parent_name]]
            if process_name in allowed_children:
                alerts.append({
                    "rule_id": "SIGMA-PARENT-002",
                    "rule_title": f"Anomalous Shell Spawned: {parent_name} -> {process_name}",
                    "severity": "HIGH",
                    "base_score": 75,
                    "mitre_tactic": "Execution / Defense Evasion",
                    "mitre_technique": "T1059 - Command and Scripting Interpreter",
                    "description": (
                        f"Detected anomalous child process '{process_name}' spawned by parent '{parent_name}'. "
                        f"Command line: '{cmdline}'"
                    )
                })

        # -------------------------------------------------------------
        # Rule 3: Encoded Command Analysis & Deobfuscation
        # -------------------------------------------------------------
        decoded_cmd = self.decode_powershell_payload(cmdline)
        if decoded_cmd:
            # Check decoded script content for malicious keywords
            malicious_indicators = ["downloadstring", "invoke-expression", "iex", "net.webclient", "bitstransfer", "virtualalloc", "createthread"]
            detected_keywords = [kw for kw in malicious_indicators if kw in decoded_cmd.lower()]
            
            severity = "CRITICAL" if detected_keywords else "HIGH"
            base_score = 85 if detected_keywords else 70

            alerts.append({
                "rule_id": "SIGMA-ENC-003",
                "rule_title": "Encoded PowerShell Command Execution Deobfuscated",
                "severity": severity,
                "base_score": base_score,
                "mitre_tactic": "Defense Evasion / Execution",
                "mitre_technique": "T1027 - Obfuscated Files or Information",
                "decoded_command": decoded_cmd,
                "description": (
                    f"PowerShell executed with encoded parameters. "
                    f"Deobfuscated Command: '{decoded_cmd[:200]}...'. "
                    f"Detected Malicious Keywords: {detected_keywords}"
                )
            })

        return alerts

sigma_rules_engine = AdvancedSigmaEngine()
