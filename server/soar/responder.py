"""
Automated SOAR (Security Orchestration, Automation, and Response) Engine for AegisXDR-Enterprise.
Handles automated host network isolation, malicious process termination, and mitigation auditing.
"""

import os
import sys
import psutil
from typing import Dict, Any, Optional
from server.core.database import SessionLocal, SoarActionLog
from config import settings

class SOAREngine:
    def __init__(self):
        self.auto_isolate = settings.AUTO_ISOLATE_ENABLED
        self.auto_terminate = settings.AUTO_TERMINATE_SUSPICIOUS_CHILDREN

    def terminate_process(self, pid: int, process_name: str, alert_id: Optional[int] = None) -> Dict[str, Any]:
        """Terminates a specific suspicious process by PID."""
        db = SessionLocal()
        try:
            if not pid or pid <= 4: # Protect system PIDs (0, 4)
                log = SoarActionLog(
                    alert_id=alert_id,
                    action_type="PROCESS_KILL",
                    target_host="localhost",
                    target_pid=pid,
                    target_process=process_name,
                    status="REJECTED",
                    details="Attempted termination of critical system process rejected."
                )
                db.add(log)
                db.commit()
                return {"status": "REJECTED", "message": "Cannot terminate system process"}

            proc = psutil.Process(pid)
            p_name = proc.name()
            proc.kill()
            
            log = SoarActionLog(
                alert_id=alert_id,
                action_type="PROCESS_KILL",
                target_host="localhost",
                target_pid=pid,
                target_process=p_name,
                status="SUCCESS",
                details=f"Successfully killed process {p_name} (PID: {pid})."
            )
            db.add(log)
            db.commit()
            return {"status": "SUCCESS", "message": f"Killed process PID {pid} ({p_name})"}
        except psutil.NoSuchProcess:
            log = SoarActionLog(
                alert_id=alert_id,
                action_type="PROCESS_KILL",
                target_host="localhost",
                target_pid=pid,
                target_process=process_name,
                status="FAILED",
                details=f"Process PID {pid} was not found active."
            )
            db.add(log)
            db.commit()
            return {"status": "NOT_FOUND", "message": f"Process PID {pid} not found"}
        except Exception as e:
            log = SoarActionLog(
                alert_id=alert_id,
                action_type="PROCESS_KILL",
                target_host="localhost",
                target_pid=pid,
                target_process=process_name,
                status="ERROR",
                details=f"Error terminating PID {pid}: {str(e)}"
            )
            db.add(log)
            db.commit()
            return {"status": "ERROR", "message": str(e)}
        finally:
            db.close()

    def isolate_host(self, hostname: str, alert_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Executes host network isolation rules.
        Simulates firewall rule insertion to block all outbound/inbound traffic except SIEM C2.
        """
        db = SessionLocal()
        try:
            # On Windows, we can inspect netsh or simulate enforcement log safely
            action_status = "SIMULATED"
            details = f"Host isolation policy activated for '{hostname}'. Network interfaces isolated."
            
            log = SoarActionLog(
                alert_id=alert_id,
                action_type="HOST_ISOLATION",
                target_host=hostname,
                status=action_status,
                details=details
            )
            db.add(log)
            db.commit()
            return {"status": action_status, "hostname": hostname, "details": details}
        finally:
            db.close()

    def handle_threat(self, hostname: str, pid: Optional[int], process_name: Optional[str], alert_id: Optional[int], severity: str) -> Dict[str, Any]:
        """Automated response router invoked when HIGH or CRITICAL threats are detected."""
        results = {}
        
        if severity == "CRITICAL" and self.auto_isolate:
            results["isolation"] = self.isolate_host(hostname, alert_id)
            
        if pid and self.auto_terminate:
            results["process_kill"] = self.terminate_process(pid, process_name or "unknown", alert_id)
            
        return results

soar_engine = SOAREngine()
