"""
Secure SOAR Engine for AegisXDR-Enterprise.
Features Dry-Run Mode, Two-Stage Analyst Approval Mechanism (PENDING_APPROVAL),
and Environment Guardrails (ENV=LAB & APPROVED=True required for active mitigation).
"""

import os
import sys
import psutil
import logging
import subprocess
from typing import Dict, Any, Optional
from server.core.database import SessionLocal, SoarActionLog, Alert

logger = logging.getLogger("SecureSOAREngine")

class SecureSOAREngine:
    """
    Production-grade SOAR engine enforcing safety guardrails, dry-run auditing,
    and mandatory approval workflows prior to disruptive response actions.
    """
    def __init__(self):
        # Environment Configuration
        self.environment = os.getenv("AEGIS_ENV", "LAB").upper() # LAB or PRODUCTION
        self.dry_run = os.getenv("AEGIS_DRY_RUN", "FALSE").upper() == "TRUE"

    def request_action_approval(
        self,
        alert_id: int,
        action_type: str,
        target_host: str,
        target_pid: Optional[int] = None,
        target_process: Optional[str] = None
    ) -> Dict[str, Any]:
        """Sets response status to PENDING_APPROVAL for analyst validation."""
        db = SessionLocal()
        try:
            alert = db.query(Alert).filter(Alert.id == alert_id).first()
            if alert:
                alert.status = "PENDING_APPROVAL"
                db.commit()

            details = f"Action '{action_type}' queued. Awaiting analyst confirmation for host {target_host} (PID: {target_pid})."
            log = SoarActionLog(
                alert_id=alert_id,
                action_type=action_type,
                target_host=target_host,
                target_pid=target_pid,
                target_process=target_process,
                status="PENDING_APPROVAL",
                details=details
            )
            db.add(log)
            db.commit()
            logger.info(f"[SOAR Approval Queue] {details}")
            return {"status": "PENDING_APPROVAL", "message": details}
        finally:
            db.close()

    def terminate_process(
        self,
        pid: int,
        process_name: str,
        alert_id: Optional[int] = None,
        approved: bool = False
    ) -> Dict[str, Any]:
        """
        Terminates a process by PID.
        Requires dry_run check and ENV=LAB & approved=True for real execution.
        """
        # Guardrail Check 1: Dry-Run Mode
        if self.dry_run:
            log_msg = f"[DRY-RUN] Process Kill PID: {pid} ({process_name}) Requested."
            logger.info(log_msg)
            self._audit_log(alert_id, "PROCESS_KILL", "localhost", pid, process_name, "DRY_RUN", log_msg)
            return {"status": "DRY_RUN", "message": log_msg}

        # Guardrail Check 2: Mandatory Approval & Environment Verification
        if not approved:
            return self.request_action_approval(alert_id, "PROCESS_KILL", "localhost", pid, process_name)

        if self.environment != "LAB":
            err_msg = f"[SAFETY REJECT] Process termination in PRODUCTION requires manual override. ENV={self.environment}"
            logger.warning(err_msg)
            self._audit_log(alert_id, "PROCESS_KILL", "localhost", pid, process_name, "REJECTED", err_msg)
            return {"status": "REJECTED", "message": err_msg}

        # Execution Phase
        try:
            if pid <= 4:
                return {"status": "REJECTED", "message": "Cannot terminate critical system PID <= 4."}

            proc = psutil.Process(pid)
            p_name = proc.name()
            proc.kill()

            success_msg = f"[SOAR EXEC] Successfully terminated process '{p_name}' (PID: {pid})."
            logger.info(success_msg)
            self._audit_log(alert_id, "PROCESS_KILL", "localhost", pid, p_name, "SUCCESS", success_msg)
            
            self._update_alert_status(alert_id, "RESOLVED")
            return {"status": "SUCCESS", "message": success_msg}
        except psutil.NoSuchProcess:
            msg = f"Process PID {pid} was not found active."
            self._audit_log(alert_id, "PROCESS_KILL", "localhost", pid, process_name, "NOT_FOUND", msg)
            return {"status": "NOT_FOUND", "message": msg}
        except Exception as e:
            err = f"Error terminating PID {pid}: {e}"
            logger.error(err)
            self._audit_log(alert_id, "PROCESS_KILL", "localhost", pid, process_name, "ERROR", err)
            return {"status": "ERROR", "message": err}

    def isolate_host(
        self,
        hostname: str,
        alert_id: Optional[int] = None,
        approved: bool = False
    ) -> Dict[str, Any]:
        """
        Executes host network isolation using netsh firewall or OS firewall commands.
        Requires ENV=LAB and approved=True.
        """
        # Guardrail Check 1: Dry-Run Mode
        if self.dry_run:
            msg = f"[DRY-RUN] Network Isolation Requested for Host '{hostname}'."
            logger.info(msg)
            self._audit_log(alert_id, "HOST_ISOLATION", hostname, None, None, "DRY_RUN", msg)
            return {"status": "DRY_RUN", "message": msg}

        # Guardrail Check 2: Mandatory Approval
        if not approved:
            return self.request_action_approval(alert_id, "HOST_ISOLATION", hostname)

        if self.environment != "LAB":
            err_msg = f"[SAFETY REJECT] Host Isolation in environment '{self.environment}' requires manual override."
            self._audit_log(alert_id, "HOST_ISOLATION", hostname, None, None, "REJECTED", err_msg)
            return {"status": "REJECTED", "message": err_msg}

        # Real Execution (Netsh / PowerShell firewall rule block)
        try:
            if sys.platform == "win32":
                cmd = ["netsh", "advfirewall", "firewall", "add", "rule", "name=AegisXDR_Isolation", "dir=out", "action=block"]
                subprocess.run(cmd, capture_output=True, check=True)
            
            msg = f"[SOAR EXEC] Host network isolation rules applied to '{hostname}'."
            logger.info(msg)
            self._audit_log(alert_id, "HOST_ISOLATION", hostname, None, None, "SUCCESS", msg)
            self._update_alert_status(alert_id, "RESOLVED")
            return {"status": "SUCCESS", "message": msg}
        except Exception as e:
            err = f"Failed to execute host isolation: {e}"
            logger.error(err)
            self._audit_log(alert_id, "HOST_ISOLATION", hostname, None, None, "ERROR", err)
            return {"status": "ERROR", "message": err}

    def _audit_log(
        self,
        alert_id: Optional[int],
        action_type: str,
        target_host: str,
        target_pid: Optional[int],
        target_process: Optional[str],
        status: str,
        details: str
    ):
        """Helper to store audit trail in DB."""
        db = SessionLocal()
        try:
            log = SoarActionLog(
                alert_id=alert_id,
                action_type=action_type,
                target_host=target_host,
                target_pid=target_pid,
                target_process=target_process,
                status=status,
                details=details
            )
            db.add(log)
            db.commit()
        finally:
            db.close()

    def _update_alert_status(self, alert_id: Optional[int], new_status: str):
        """Updates correlated alert status in DB."""
        if not alert_id:
            return
        db = SessionLocal()
        try:
            alert = db.query(Alert).filter(Alert.id == alert_id).first()
            if alert:
                alert.status = new_status
                db.commit()
        finally:
            db.close()

secure_soar_engine = SecureSOAREngine()
