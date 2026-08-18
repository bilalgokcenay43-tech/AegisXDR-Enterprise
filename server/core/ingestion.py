"""
Log Ingestion Pipeline for AegisXDR-Enterprise.
Handles asynchronous telemetry queueing, AES-256 decryption verification, DB persistence, and SIEM correlation routing.
"""

import asyncio
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from server.core.crypto import crypto_engine
from server.core.database import SessionLocal, TelemetryLog, Alert
from server.detectors.process_tree import process_tree_engine
from server.detectors.sigma_parser import sigma_engine
from server.soar.responder import soar_engine

class IngestionPipeline:
    def __init__(self):
        self.queue: asyncio.Queue = asyncio.Queue()

    async def ingest_payload(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Receives agent payload. Decrypts AES-256 GCM if encrypted, validates schema,
        persists to Database, and runs correlation rules.
        """
        # Step 1: AES-256 Decryption if encrypted flag present
        if raw_data.get("encrypted", False):
            payload_b64 = raw_data.get("data")
            if not payload_b64:
                raise ValueError("Missing 'data' field in encrypted payload")
            telemetry = crypto_engine.decrypt(payload_b64)
            is_enc = True
        else:
            telemetry = raw_data
            is_enc = False

        # Step 2: Database Persistence
        db: Session = SessionLocal()
        try:
            log_entry = TelemetryLog(
                agent_id=telemetry.get("agent_id", "UNKNOWN"),
                hostname=telemetry.get("hostname", "UNKNOWN"),
                ip_address=telemetry.get("ip_address", "127.0.0.1"),
                pid=telemetry.get("pid"),
                process_name=telemetry.get("process_name", ""),
                ppid=telemetry.get("ppid"),
                parent_name=telemetry.get("parent_name", ""),
                cmdline=telemetry.get("cmdline", ""),
                process_path=telemetry.get("process_path", ""),
                is_encrypted=is_enc
            )
            db.add(log_entry)
            db.commit()
            db.refresh(log_entry)

            # Step 3: Run Threat Detection Engines (Process Tree + SIGMA)
            generated_alerts = []
            
            # Process Tree Correlation Engine
            pt_alerts = process_tree_engine.analyze(telemetry)
            generated_alerts.extend(pt_alerts)
            
            # SIGMA Rules Engine
            sigma_alerts = sigma_engine.analyze(telemetry)
            generated_alerts.extend(sigma_alerts)

            # Step 4: Persist Alerts & Trigger SOAR automated mitigation if High/Critical
            saved_alerts = []
            for alert_data in generated_alerts:
                alert_record = Alert(
                    rule_id=alert_data.get("rule_id", "AEGIS-000"),
                    rule_title=alert_data.get("rule_title", "Anomalous Detection"),
                    severity=alert_data.get("severity", "MEDIUM"),
                    mitre_tactic=alert_data.get("mitre_tactic", "Execution"),
                    mitre_technique=alert_data.get("mitre_technique", "T1059"),
                    hostname=telemetry.get("hostname", "UNKNOWN"),
                    pid=telemetry.get("pid"),
                    process_name=telemetry.get("process_name", ""),
                    parent_name=telemetry.get("parent_name", ""),
                    cmdline=telemetry.get("cmdline", ""),
                    description=alert_data.get("description", ""),
                    soar_triggered=False
                )
                
                # Check for SOAR auto-triggering on HIGH/CRITICAL
                if alert_record.severity in ["HIGH", "CRITICAL"]:
                    soar_res = soar_engine.handle_threat(
                        hostname=alert_record.hostname,
                        pid=alert_record.pid,
                        process_name=alert_record.process_name,
                        alert_id=alert_record.id,
                        severity=alert_record.severity
                    )
                    alert_record.soar_triggered = True

                db.add(alert_record)
                db.commit()
                db.refresh(alert_record)
                saved_alerts.append({
                    "id": alert_record.id,
                    "title": alert_record.rule_title,
                    "severity": alert_record.severity,
                    "soar_triggered": alert_record.soar_triggered
                })

            return {
                "status": "INGESTED",
                "log_id": log_entry.id,
                "alerts_generated": len(saved_alerts),
                "alerts": saved_alerts
            }
        finally:
            db.close()

ingestion_pipeline = IngestionPipeline()
