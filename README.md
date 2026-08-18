# AegisXDR-Enterprise 🛡️

**AegisXDR-Enterprise** is a production-grade, hybrid Next-Gen SIEM / XDR (Extended Detection & Response) enterprise platform built for real-time threat ingestion, behavioral process tree correlation, SIGMA rule parsing, AES-256 encrypted telemetry, and automated SOAR response.

---

## 🏛️ Architecture Overview

```
+-----------------------------------------------------------------------------------+
|                            Endpoint Collector Agent                               |
|   - Process Tree Monitoring (Parent-Child PIDs)                                  |
|   - Obfuscated CLI Flag Detection (-enc, -w hidden, downloadstring)              |
|   - Payload Encryption: AES-256 GCM (12-byte Nonce + Auth Tag)                   |
+----------------------------------------+------------------------------------------+
                                         |
                                         | HTTP POST /api/v1/telemetry (AES-256 B64)
                                         v
+-----------------------------------------------------------------------------------+
|                           AegisXDR Core Ingestion Engine                          |
|   - Async Python FastAPI Core                                                     |
|   - AES-256 Decryptor & Payload Validation                                       |
|   - SQLite / SQLAlchemy Persistence Layer                                         |
+----------------------------------------+------------------------------------------+
                                         |
                       +-----------------+-----------------+
                       |                                   |
                       v                                   v
+------------------------------------+   +------------------------------------+
|   Process Tree Correlation Engine  |   |         SIGMA Rule Parser Engine   |
| - Catches winword.exe -> powershell|   | - YAML SIGMA Rule Parsing          |
| - Detects command line obfuscation |   | - Multi-field & Modifier Matcher   |
+------------------+-----------------+   +------------------+-----------------+
                   |                                        |
                   +-------------------+--------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------------+
|                        Automated SOAR Responder Engine                            |
| - Evaluates Severity (HIGH / CRITICAL)                                            |
| - Automated Malicious Process Termination (psutil kill)                           |
| - Automated Host Network Isolation                                                |
| - Audit Logging & Mitigation Actions                                              |
+----------------------------------------+------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                          Modern SOC Dashboard Interface                           |
| - Dark Cyberpunk Theme (Tailwind CSS, Glassmorphism, Lucide Icons)                 |
| - Real-time Threat Metrics & Live Telemetry Stream Feed                           |
| - Chart.js Visualizations (Severity Doughnut & Ingestion Rate Line)               |
| - Interactive SOAR Triggers & One-Click Threat Simulation                         |
+-----------------------------------------------------------------------------------+
```

---

## 📁 Directory Structure

```
c:\Users\pc\Desktop\SentinelCore-XDR\
├── agent\
│   ├── collector.py           # Endpoint agent scanner & telemetry transmitter
│   ├── crypto_utils.py        # Client-side AES-256 GCM encryption helper
│   └── agent_config.json      # Collector agent configuration
├── server\
│   ├── main.py                # FastAPI main app, REST APIs, and dashboard routes
│   ├── core\
│   │   ├── crypto.py          # AES-256 GCM decryption engine
│   │   ├── database.py        # SQLite SQLAlchemy ORM models (Telemetry, Alerts, SOAR logs)
│   │   └── ingestion.py       # Ingestion pipeline & orchestrator
│   ├── detectors\
│   │   ├── sigma_parser.py    # Standard SIGMA YAML detection rule parser & matcher
│   │   ├── process_tree.py    # Parent-Child anomaly & CLI obfuscation correlation engine
│   │   └── rules\             # SIGMA YAML rule definitions
│   │       ├── powershell_encoded.yml
│   │       ├── office_spawning_cmd.yml
│   │       └── lsass_memory_dump.yml
│   └── soar\
│       └── responder.py       # Automated host network isolation & process termination handler
├── templates\
│   └── dashboard.html         # Modern SOC Command Center Dashboard (Tailwind CSS + Chart.js)
├── static\
│   ├── css\
│   │   └── style.css          # Custom dark cyber glassmorphism styles
│   └── js\
│       └── dashboard.js        # Dynamic UI polling, Chart.js updates, & SOAR controls
├── config.py                  # Centralized configuration (AES keys, DB paths, detectors)
├── requirements.txt           # Dependency requirements
└── README.md                  # Comprehensive Architecture documentation
```

---

## 🚀 Quick Start & Installation

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Launch AegisXDR Core Server
```bash
python server/main.py
# Server starts at http://127.0.0.1:8000
```
Open your browser and navigate to **`http://127.0.0.1:8000`** to access the SOC Command Center.

### 3. Run Endpoint Collector Agent
In a separate terminal:
```bash
# Run continuous monitoring scan
python agent/collector.py --continuous

# Or simulate a synthetic malware attack (winword spawning powershell -enc)
python agent/collector.py --simulate-attack
```

---

## 🔌 API Endpoints Summary

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Renders SOC Command Center UI Dashboard |
| `POST` | `/api/v1/telemetry` | Ingests AES-256 encrypted or unencrypted agent telemetry |
| `GET` | `/api/v1/alerts` | Retrieves correlated SIEM alerts (supports severity filtering) |
| `GET` | `/api/v1/telemetry` | Retrieves recent process telemetry records |
| `GET` | `/api/v1/stats` | Retrieves top-level dashboard threat metrics |
| `GET` | `/api/v1/soar/actions` | Retrieves SOAR mitigation audit logs |
| `POST` | `/api/v1/soar/isolate` | Triggers host network isolation for a target hostname |
| `POST` | `/api/v1/soar/kill-process` | Terminates a target process by PID |

---

## 🛡️ Detection Engine Features

1. **Process Tree Correlation**:
   - Detects suspicious parent-child execution chains (e.g., `winword.exe` spawning `powershell.exe`, `excel.exe` spawning `cmd.exe`).
   - Flags suspicious command line parameters (`-enc`, `-w hidden`, `-noprofile`, `downloadstring`, `vssadmin delete shadows`).
2. **SIGMA Detection Parser**:
   - Fully parses standard YAML SIGMA rules.
   - Evaluates field modifiers (`Image|endswith`, `CommandLine|contains`, `re`).
3. **SOAR Mitigation**:
   - Automatically executes host isolation and process termination when `HIGH` or `CRITICAL` threats are triggered.
   - Logs all automated and manual SOAR actions for compliance and auditing.
