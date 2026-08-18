"""
Database Persistence & Data Models for AegisXDR-Enterprise.
Stores process telemetry, correlation alerts, and SOAR mitigation logs.
"""

from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker
from config import settings

Base = declarative_base()

class TelemetryLog(Base):
    __tablename__ = "telemetry_logs"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(100), index=True)
    hostname = Column(String(100), index=True)
    ip_address = Column(String(45))
    timestamp = Column(DateTime, default=datetime.utcnow)
    pid = Column(Integer)
    process_name = Column(String(255))
    ppid = Column(Integer)
    parent_name = Column(String(255))
    cmdline = Column(Text)
    process_path = Column(Text)
    is_encrypted = Column(Boolean, default=True)

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    rule_id = Column(String(100), index=True)
    rule_title = Column(String(255))
    severity = Column(String(20), index=True) # LOW, MEDIUM, HIGH, CRITICAL
    mitre_tactic = Column(String(100))
    mitre_technique = Column(String(100))
    hostname = Column(String(100))
    pid = Column(Integer)
    process_name = Column(String(255))
    parent_name = Column(String(255))
    cmdline = Column(Text)
    description = Column(Text)
    soar_triggered = Column(Boolean, default=False)
    status = Column(String(50), default="NEW") # NEW, INVESTIGATING, RESOLVED

class SoarActionLog(Base):
    __tablename__ = "soar_action_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    alert_id = Column(Integer, nullable=True)
    action_type = Column(String(50)) # HOST_ISOLATION, PROCESS_KILL, PORT_BLOCK
    target_host = Column(String(100))
    target_pid = Column(Integer, nullable=True)
    target_process = Column(String(255), nullable=True)
    status = Column(String(20)) # SUCCESS, FAILED, SIMULATED
    details = Column(Text)

# Initialize Engine and Session
engine = create_engine(settings.DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
