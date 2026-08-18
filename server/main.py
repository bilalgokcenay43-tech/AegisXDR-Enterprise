"""
FastAPI Server Entry Point for AegisXDR-Enterprise.
Provides RESTful APIs for log ingestion, SIEM correlation, dynamic risk scoring,
SOAR mitigation approvals, memory forensics, timeline visualization, and root cause analysis.
"""

import os
import sys
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from fastapi import FastAPI, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import settings
from server.core.database import init_db, get_db, TelemetryLog, Alert, SoarActionLog
from collectors.fp_engine import fp_engine
from detection.sigma_rules import sigma_rules_engine
from detection.risk_engine import risk_engine
from soar.soar_engine import secure_soar_engine
from hunting.enrichment import enricher
from hunting.memory_hunter import memory_hunter

app = FastAPI(
    title=settings.PROJECT_NAME,
    version="2.0.0",
    description="Hybrid Next-Gen SIEM/XDR Enterprise Engine with Dynamic Risk Scoring, Memory Hunting, and Secure SOAR"
)

# Setup Templates and Static Files
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
static_dir = os.path.join(BASE_DIR, "static")

if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.on_event("startup")
def startup_event():
    """Initializes SQLite Database schema on application launch."""
    init_db()
    print(f"[*] {settings.PROJECT_NAME} Production Engine Active.")

# ==================== SOC DASHBOARD ROUTE ====================

@app.get("/", response_class=HTMLResponse)
async def get_dashboard(request: Request):
    """Renders modern SOC Dashboard interface."""
    return templates.TemplateResponse("dashboard.html", {"request": request, "project_name": settings.PROJECT_NAME})

# ==================== API ENDPOINTS ====================

@app.post("/api/v1/telemetry")
async def post_telemetry(payload: Dict[str, Any], db: Session = Depends(get_db)):
    """
    Ingests agent telemetry events. Supports FP filtering, SIGMA evaluation,
    Dynamic Risk Scoring, Alert Enrichment, and SOAR routing.
    """
    try:
        # Step 1: Check False Positive Whitelist Engine
        is_fp, fp_rule_name = fp_engine.is_false_positive(payload)
        if is_fp:
            return JSONResponse(status_code=200, content={"status": "IGNORED_FALSE_POSITIVE", "rule": fp_rule_name})

        # Step 2: Persist Telemetry Log
        log_entry = TelemetryLog(
            agent_id=payload.get("agent_id", "UNKNOWN"),
            hostname=payload.get("hostname", "UNKNOWN"),
            ip_address=payload.get("ip_address", "127.0.0.1"),
            pid=payload.get("pid"),
            process_name=payload.get("process_name", ""),
            ppid=payload.get("ppid"),
            parent_name=payload.get("parent_name", ""),
            cmdline=payload.get("cmdline", ""),
            process_path=payload.get("process_path", ""),
            is_encrypted=payload.get("encrypted", False)
        )
        db.add(log_entry)
        db.commit()
        db.refresh(log_entry)

        # Step 3: Run Advanced SIGMA & Rule Engine
        generated_alerts = sigma_rules_engine.evaluate_event(payload)
        saved_alerts = []

        for alert_data in generated_alerts:
            # Step 4: Enrich Alert (MISP, GeoIP, Privilege)
            enriched_alert = enricher.enrich_alert(alert_data, payload)

            # Step 5: Dynamic Risk Scoring Calculation
            base_score = alert_data.get("base_score", 60.0)
            threat_intel_matched = enriched_alert.get("threat_intel_matched", False)
            
            risk_res = risk_engine.calculate_score(
                base_score=base_score,
                hostname=payload.get("hostname", "WORKSTATION"),
                threat_intel_matched=threat_intel_matched
            )

            severity = risk_res["severity"]
            recommended_action = risk_res["recommended_action"]

            alert_record = Alert(
                rule_id=alert_data.get("rule_id", "AEGIS-000"),
                rule_title=alert_data.get("rule_title", "Anomalous Security Detection"),
                severity=severity,
                mitre_tactic=alert_data.get("mitre_tactic", "Execution"),
                mitre_technique=alert_data.get("mitre_technique", "T1059"),
                hostname=payload.get("hostname", "UNKNOWN"),
                pid=payload.get("pid"),
                process_name=payload.get("process_name", ""),
                parent_name=payload.get("parent_name", ""),
                cmdline=payload.get("cmdline", ""),
                description=f"{alert_data.get('description', '')} | Risk Score: {risk_res['risk_score']} | Privilege: {enriched_alert.get('privilege_level', 'Standard')}",
                soar_triggered=False,
                status="NEW"
            )
            db.add(alert_record)
            db.commit()
            db.refresh(alert_record)

            # Step 6: SOAR Response Routing based on Risk Score Action Tier
            if recommended_action == "AUTO_SOAR":
                secure_soar_engine.terminate_process(
                    pid=alert_record.pid,
                    process_name=alert_record.process_name,
                    alert_id=alert_record.id,
                    approved=True
                )
                alert_record.soar_triggered = True
                db.commit()
            elif recommended_action == "REQUIRE_APPROVAL":
                secure_soar_engine.request_action_approval(
                    alert_id=alert_record.id,
                    action_type="PROCESS_KILL",
                    target_host=alert_record.hostname,
                    target_pid=alert_record.pid,
                    target_process=alert_record.process_name
                )

            saved_alerts.append({
                "id": alert_record.id,
                "title": alert_record.rule_title,
                "severity": alert_record.severity,
                "risk_score": risk_res["risk_score"],
                "action": recommended_action
            })

        return JSONResponse(status_code=200, content={
            "status": "INGESTED",
            "log_id": log_entry.id,
            "alerts_generated": len(saved_alerts),
            "alerts": saved_alerts
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ingestion Error: {str(e)}")

@app.get("/api/v1/alerts")
def get_alerts(
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db)
):
    """Retrieves correlated alerts."""
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity.upper())
    if status:
        query = query.filter(Alert.status == status.upper())
    
    alerts = query.order_by(Alert.timestamp.desc()).limit(limit).all()
    
    return [
        {
            "id": a.id,
            "timestamp": a.timestamp.isoformat() if a.timestamp else None,
            "rule_id": a.rule_id,
            "rule_title": a.rule_title,
            "severity": a.severity,
            "mitre_tactic": a.mitre_tactic,
            "mitre_technique": a.mitre_technique,
            "hostname": a.hostname,
            "pid": a.pid,
            "process_name": a.process_name,
            "parent_name": a.parent_name,
            "cmdline": a.cmdline,
            "description": a.description,
            "soar_triggered": a.soar_triggered,
            "status": a.status
        }
        for a in alerts
    ]

@app.get("/api/v1/alerts/{alert_id}/root-cause")
def get_alert_root_cause(alert_id: int, db: Session = Depends(get_db)):
    """Provides Root Cause Analysis and Process Tree hierarchy for an alert."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Fetch parent telemetry if available
    parent_logs = db.query(TelemetryLog).filter(
        TelemetryLog.hostname == alert.hostname,
        TelemetryLog.process_name == alert.parent_name
    ).order_by(TelemetryLog.timestamp.desc()).limit(3).all()

    return {
        "alert_id": alert.id,
        "root_cause_summary": f"Process '{alert.process_name}' (PID: {alert.pid}) executed under parent process '{alert.parent_name}'. Detected MITRE Technique: {alert.mitre_technique}.",
        "process_tree": {
            "parent": {
                "name": alert.parent_name or "unknown_parent.exe",
                "logs_found": len(parent_logs)
            },
            "target_process": {
                "pid": alert.pid,
                "name": alert.process_name,
                "cmdline": alert.cmdline
            }
        },
        "raw_alert_data": {
            "rule_id": alert.rule_id,
            "rule_title": alert.rule_title,
            "severity": alert.severity,
            "description": alert.description,
            "timestamp": alert.timestamp.isoformat() if alert.timestamp else None
        }
    }

@app.get("/api/v1/alerts/{alert_id}/timeline")
def get_alert_timeline(alert_id: int, db: Session = Depends(get_db)):
    """Generates chronological timeline of system events +/- 5 minutes around the alert."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert_time = alert.timestamp or datetime.utcnow()
    start_time = alert_time - timedelta(minutes=5)
    end_time = alert_time + timedelta(minutes=5)

    timeline_events = db.query(TelemetryLog).filter(
        TelemetryLog.hostname == alert.hostname,
        TelemetryLog.timestamp >= start_time,
        TelemetryLog.timestamp <= end_time
    ).order_by(TelemetryLog.timestamp.asc()).all()

    return [
        {
            "id": t.id,
            "timestamp": t.timestamp.isoformat() if t.timestamp else None,
            "process_name": t.process_name,
            "parent_name": t.parent_name,
            "pid": t.pid,
            "cmdline": t.cmdline,
            "is_target_alert_event": (t.pid == alert.pid and t.process_name == alert.process_name)
        }
        for t in timeline_events
    ]

@app.post("/api/v1/soar/approve")
def approve_soar_action(payload: Dict[str, Any]):
    """Confirms analyst approval for a PENDING_APPROVAL SOAR mitigation action."""
    alert_id = payload.get("alert_id")
    action_type = payload.get("action_type", "PROCESS_KILL")
    pid = payload.get("pid")
    process_name = payload.get("process_name", "unknown")
    hostname = payload.get("hostname", "localhost")

    if not alert_id:
        raise HTTPException(status_code=400, detail="alert_id required")

    if action_type == "PROCESS_KILL" and pid:
        res = secure_soar_engine.terminate_process(pid=pid, process_name=process_name, alert_id=alert_id, approved=True)
    elif action_type == "HOST_ISOLATION":
        res = secure_soar_engine.isolate_host(hostname=hostname, alert_id=alert_id, approved=True)
    else:
        raise HTTPException(status_code=400, detail="Invalid action parameters")

    return res

@app.post("/api/v1/hunting/memory-scan")
def trigger_memory_scan(payload: Dict[str, Any]):
    """Triggers live YARA memory forensic audit on target PID."""
    pid = payload.get("pid")
    if not pid:
        raise HTTPException(status_code=400, detail="PID required")
    res = memory_hunter.scan_process_memory(pid)
    return res

@app.get("/api/v1/stats")
def get_stats(db: Session = Depends(get_db)):
    """Provides dashboard top bar stats."""
    return {
        "total_telemetry_events": db.query(TelemetryLog).count(),
        "total_alerts": db.query(Alert).count(),
        "critical_alerts": db.query(Alert).filter(Alert.severity == "CRITICAL").count(),
        "high_alerts": db.query(Alert).filter(Alert.severity == "HIGH").count(),
        "soar_actions_executed": db.query(SoarActionLog).count(),
        "status": "ACTIVE"
    }

@app.get("/api/v1/soar/actions")
def get_soar_actions(limit: int = Query(50), db: Session = Depends(get_db)):
    """Retrieves SOAR audit log entries."""
    actions = db.query(SoarActionLog).order_by(SoarActionLog.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": act.id,
            "timestamp": act.timestamp.isoformat() if act.timestamp else None,
            "alert_id": act.alert_id,
            "action_type": act.action_type,
            "target_host": act.target_host,
            "target_pid": act.target_pid,
            "target_process": act.target_process,
            "status": act.status,
            "details": act.details
        }
        for act in actions
    ]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server.main:app", host=settings.HOST, port=settings.PORT, reload=True)
