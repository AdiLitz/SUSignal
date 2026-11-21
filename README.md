# 5G Sentinel – Intelligent 5G Network Security Misconfiguration Scanner

5G Sentinel is an automated cybersecurity assessment tool designed to scan, detect, and remediate security misconfigurations across 5G Core Network Functions (NFs). 

By evaluating configuration artifacts against 3GPP security standards (such as 3GPP TS 33.501), 5G Sentinel identifies dangerous weaknesses such as null encryption, insecure Service Based Interface (SBI) transport schemes, open interface bindings, and permissive inter-NF mutual TLS policies before they can be exploited in simulated or lab deployments.

---

## 1. Project Overview

Modern 5G Standalone (SA) architectures rely on distributed cloud-native Network Functions (AMF, SMF, UPF, NRF, AUSF, UDM). A single configuration oversight (e.g., exposing an unauthenticated SBI or prioritizing `NEA0` null encryption) can compromise subscriber confidentiality or allow rogue NF registration.

5G Sentinel parses multi-format configuration files, evaluates them with a modular rule engine, categorizes risk into standard severity levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), logs scan history in SQLite, and provides actionable remediation guidance via a responsive cybersecurity dashboard.

---

## 2. Project Architecture

The architecture enforces strict decoupling between the ingestion layer, analysis engine, database persistence, and presentation tier:

```
[ Frontend: React + Vite + Tailwind ]
                  |
         REST API (HTTP / JSON)
                  v
       [ FastAPI: main.py ]
                  |
       [ routes/scanner.py ]
         /               \
        v                 v
 [ parser.py ]    [ database/db.py (SQLite) ]
        |
        v
 [ analyzer.py ] <--> [ rules.py & risk.py ]
        ^
        | (Phase 2 Extension Point)
 [ integrations/ : Open5GS & free5GC Adapters ]
```

- **Frontend:** Isolated React.js single-page application communicating via a dedicated API client service.
- **Backend API:** FastAPI application providing endpoint validation, error handling, and CORS middleware.
- **Scanner Core:** Independent Python parser and modular rule evaluator.
- **Persistence:** Lightweight SQLite database recording scan summaries and individual vulnerability findings.
- **Integrations:** Decoupled adapter layer reserved for importing configurations directly from open-source 5G Cores.

---

## 3. Technology Stack

- **Frontend:** React.js, Vite, JavaScript, Tailwind CSS, Recharts, Lucide Icons.
- **Backend:** Python 3.10+, FastAPI, Uvicorn, Pydantic.
- **Configuration Parsing:** PyYAML (YAML), Python standard library `json` (JSON).
- **Database:** SQLite (embedded).
- **Documentation:** Markdown architectural specifications and OpenAPI / Swagger docs.

---

## 4. Directory Structure

```
5G-Sentinel/
├── frontend/                     # React + Vite web dashboard
│   ├── src/
│   │   ├── components/           # Navbar, UploadSection, VulnerabilityStats, ScanResults
│   │   ├── pages/                # Dashboard.jsx
│   │   ├── services/             # Centralized API service layer (api.js)
│   │   ├── assets/               # Static assets
│   │   ├── App.jsx               # Application root component
│   │   ├── main.jsx              # DOM entry point
│   │   └── index.css             # Tailwind styling and custom theme
│   ├── public/                   # Public web assets
│   ├── index.html                # HTML document entry
│   ├── package.json              # Frontend dependencies and scripts
│   ├── vite.config.js            # Vite configuration
│   └── tailwind.config.js        # Theme color definitions (navy, cyan)
├── backend/                      # Python FastAPI scanner backend
│   ├── app/
│   │   ├── main.py               # FastAPI entry, CORS, lifespan, /api/health
│   │   ├── routes/
│   │   │   └── scanner.py        # POST /api/scan/upload & GET /api/scan/history
│   │   ├── scanner/
│   │   │   ├── parser.py         # YAML/JSON parser & NF type detection
│   │   │   ├── analyzer.py       # Rule orchestration & posture scoring
│   │   │   ├── rules.py          # Modular 3GPP security detection rules
│   │   │   └── risk.py           # Severity enums and weighting factors
│   │   ├── database/
│   │   │   └── db.py             # SQLite initialization and scan history persistence
│   │   └── integrations/
│   │       └── __init__.py       # Phase 2 Open5GS & free5GC adapter interfaces
│   ├── sample_configs/           # Sample YAML & JSON test configurations
│   │   ├── amf_vulnerable.yaml
│   │   ├── amf_hardened.yaml
│   │   ├── smf_sample.json
│   │   └── README.md
│   └── requirements.txt          # Python dependencies
├── docs/                         # Technical documentation
│   ├── architecture.md           # System design & 4-developer ownership matrix
│   └── api-contract.md           # Comprehensive API schema and payload contracts
├── .gitignore                    # Git ignore file for Python, Node, Vite, DB
├── .env.example                  # Environment configuration template
└── README.md                     # Project reference and team guide
```

---

## 5. How to Install Dependencies

### Prerequisites
- Python 3.10 or higher
- Node.js 18 or higher (with npm)

### Backend Dependencies
From the repository root:
```bash
cd backend
python -m pip install -r requirements.txt
cd ..
```

### Frontend Dependencies
From the repository root:
```bash
cd frontend
npm install
cd ..
```

---

## 6. How to Start the Backend

From the repository root:
```bash
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

- API Base URL: `http://localhost:8000`
- Interactive Swagger UI Docs: `http://localhost:8000/docs`
- Health Endpoint: `http://localhost:8000/api/health`

---

## 7. How to Start the Frontend

From the repository root:
```bash
cd frontend
npm run dev
```

- Web Dashboard URL: `http://localhost:5173`

---

## 8. Current Implementation Status

| Feature / Component | Status | Description |
| :--- | :--- | :--- |
| **Backend API Gateway** | Complete | FastAPI with CORS, health-check (`/api/health`), and modular routing. |
| **Config Parsers** | Complete | Safe deserialization for YAML and JSON with format validation. |
| **Security Rule Engine** | Complete (Starter) | Modular rule structure with starter rules (NEA0, plaintext SBI, 0.0.0.0 bind, mTLS). |
| **Severity Classification** | Complete | Risk levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and health score calculator. |
| **SQLite Persistence** | Complete | Stores scan history, severity counts, and individual finding records. |
| **Frontend Dashboard** | Complete | Dark cybersecurity theme (navy/cyan), file dropzone, stats breakdown, Recharts chart. |
| **API Client Layer** | Complete | Centralized `services/api.js` for clean frontend/backend decoupling. |
| **Sample Test Configs** | Complete | Vulnerable and hardened AMF/SMF configurations provided in `sample_configs/`. |

---

## 9. Planned Open5GS & free5GC Integration (Phase 2)

5G Sentinel is architected to inspect configurations extracted from real open-source 5G Core implementations:

1. **Open5GS Integration:**
   - Ingesting `/etc/open5gs/*.yaml` configuration files directly from simulated testbeds.
2. **free5GC Integration:**
   - Ingesting free5GC Kubernetes ConfigMaps or standalone YAML dumps.

### How the Architecture Accommodates This:
- The core scanner requires **no direct dependency or deployment** of Open5GS or free5GC.
- The `backend/app/integrations/` module defines the `Base5GCoreAdapter` interface.
- Phase 2 adapters will read platform-specific configuration formats and convert them into the standard dictionary schema consumed by `scanner/analyzer.py`.
