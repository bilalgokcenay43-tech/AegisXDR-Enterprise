"""
Process Tree Correlation Engine for AegisXDR-Enterprise.
Detects anomalous parent-child execution relationships and suspicious CLI parameter obfuscation.
"""

from typing import Dict, Any, List
from config import settings

class ProcessTreeEngine:
    def __init__(self):
        self.suspicious_pairs = settings.SUSPICIOUS_PARENT_CHILD
        self.suspicious_flags = settings.SUSPICIOUS_CLI_FLAGS

    def analyze(self, process_event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyzes a single process event for parent-child anomalies and CLI obfuscation flags.
        Returns a list of alert dictionaries.
        """
        alerts = []
        
        parent = (process_event.get("parent_name") or "").lower()
        child = (process_event.get("process_name") or "").lower()
        cmdline = (process_event.get("cmdline") or "").lower()
        pid = process_event.get("pid")
        ppid = process_event.get("ppid")

        # Check 1: Parent-Child Anomaly Detection
        for entry in self.suspicious_pairs:
            target_parent = entry["parent"].lower()
            target_children = [c.lower() for c in entry["child"]]

            if parent == target_parent and child in target_children:
                alerts.append({
                    "rule_id": "AEGIS-PROC-001",
                    "rule_title": f"Anomalous Process Tree: {parent} spawned {child}",
                    "severity": "HIGH",
                    "mitre_tactic": "Execution / Defense Evasion",
                    "mitre_technique": "T1059.001 - Command and Scripting Interpreter",
                    "description": (
                        f"Detected suspicious parent process '{parent}' (PID: {ppid}) "
                        f"spawning shell interpreter '{child}' (PID: {pid}). "
                        f"Command line: '{cmdline}'"
                    )
                })

        # Check 2: Suspicious CLI Flags & Encoded Command Detection
        detected_flags = [flag for flag in self.suspicious_flags if flag.lower() in cmdline]
        
        if detected_flags:
            # Determine severity based on specific flags
            severity = "CRITICAL" if any(f in ["-enc", "-encodedcommand", "downloadstring", "vssadmin"] for f in detected_flags) else "MEDIUM"
            
            alerts.append({
                "rule_id": "AEGIS-CLI-002",
                "rule_title": f"Suspicious Command Line Execution ({', '.join(detected_flags)})",
                "severity": severity,
                "mitre_tactic": "Defense Evasion / Execution",
                "mitre_technique": "T1027 - Obfuscated Files or Information",
                "description": (
                    f"Process '{child}' (PID: {pid}) executed with suspicious CLI flags: "
                    f"{', '.join(detected_flags)}. Full command line: '{cmdline}'"
                )
            })

        return alerts

process_tree_engine = ProcessTreeEngine()
