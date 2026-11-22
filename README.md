# SUSignal – Intelligent 5G Network Security Misconfiguration Scanner

SUSignal is an automated cybersecurity assessment tool designed to scan, detect, and remediate security misconfigurations across 5G Core Network Functions (NFs). 

By evaluating configuration artifacts against 3GPP security standards (such as 3GPP TS 33.501), SUSignal identifies dangerous weaknesses such as null encryption, insecure Service Based Interface (SBI) transport schemes, open interface bindings, and permissive inter-NF mutual TLS policies before they can be exploited in simulated or lab deployments.

---

## 1. Project Overview

Modern 5G Standalone (SA) architectures rely on distributed cloud-native Network Functions (AMF, SMF, UPF, NRF, AUSF, UDM). A single configuration oversight (e.g., exposing an unauthenticated SBI or prioritizing `NEA0` null encryption) can compromise subscriber confidentiality or allow rogue NF registration.

SUSignal parses multi-format configuration files, evaluates them with a modular rule engine, categorizes risk into standard severity levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), logs scan history in SQLite, and provides actionable remediation guidance via a responsive cybersecurity dashboard.

---

## 2. Project Architecture

The architecture enforces strict decoupling between the ingestion layer, analysis engine, database persistence, and presentation tier:

```
[ Frontend: Vite-hosted SUSignal dashboard ]
                  |
         REST API (HTTP / JSON)
                  v
       [ FastAPI: main.py ]
                  |
       [ routes/scanner.py ]       [ routes/environments.py ]
                 |                             |
                 v                             v
       [ parser -> analyzer ]       [ Open5GS Alpha manager ]
                 |                  [ runtime assessment ]
                 +-------------+---------------+
                               v
                  [ database/db.py (SQLite) ]
```

- **Frontend:** The active dashboard is the vanilla JavaScript application in `frontend/index.html` and `frontend/src/app.js`, served by Vite and connected through `frontend/src/services/api.js`. The alternative React source is retained but is not the active entry point.
- **Backend API:** FastAPI application providing endpoint validation, error handling, and CORS middleware.
- **Scanner Core:** Independent Python parser and modular rule evaluator.
- **Persistence:** Lightweight SQLite database recording scan summaries and individual vulnerability findings.
- **Integrations:** Network Alpha is controlled through a fixed-operation Docker Compose manager. Runtime assessments are evaluated and persisted separately from uploaded configuration scans.

---

## 3. Technology Stack

- **Frontend:** Vite, JavaScript, CSS, plus the retained React/Tailwind/Recharts prototype source.
- **Backend:** Python 3.10+, FastAPI, Uvicorn, Pydantic.
- **Configuration Parsing:** PyYAML (YAML), Python standard library `json` (JSON).
- **Database:** SQLite (embedded).
- **Documentation:** Markdown architectural specifications and OpenAPI / Swagger docs.

---

## 4. Directory Structure

```
SUSignal/
├── frontend/                     # Vite-hosted SUSignal dashboard and retained React source
│   ├── src/
│   │   ├── app.js                # Active vanilla JavaScript dashboard
│   │   └── services/api.js       # Centralized backend API client
│   ├── public/                   # Styles, assets, and sample configuration library
│   ├── index.html                # Active dashboard entry point
│   ├── package.json              # Frontend dependencies and scripts
│   ├── vite.config.js            # Vite configuration
│   └── tailwind.config.js        # Theme color definitions (navy, cyan)
├── backend/                      # Python FastAPI scanner backend
│   ├── app/
│   │   ├── main.py               # FastAPI entry, CORS, lifespan, /api/health
│   │   ├── routes/
│   │   │   ├── scanner.py        # Upload, history, analytics, rule catalog, remediation APIs
│   │   │   └── environments.py   # Network Alpha status, lifecycle, runtime APIs
│   │   ├── scanner/
│   │   │   ├── parser.py         # YAML/JSON parser & NF type detection
│   │   │   ├── analyzer.py       # Rule orchestration & posture scoring
│   │   │   ├── runtime_assessment.py # Network Alpha runtime checks
│   │   │   ├── rules.py          # Modular 3GPP security detection rules
│   │   │   └── risk.py           # Severity enums and weighting factors
│   │   ├── database/
│   │   │   └── db.py             # SQLite initialization and scan history persistence
│   │   └── integrations/
│   │       └── open5gs_alpha.py  # Fixed Docker Compose operations for Alpha
│   └── requirements.txt          # Python dependencies
├── deployments/
│   └── open5gs/network-alpha/    # Isolated Compose deployment for Network Alpha
│       └── compose.yaml
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
- Backend URL defaults to `http://localhost:8000`. To override it, copy `frontend/.env.example` to `frontend/.env.local` and edit `VITE_API_BASE_URL`.

The history API supports pagination, filename/NF/severity filtering, and date/score sorting. Each record includes its assessment type (`configuration` or `runtime`), Network Function/network, findings counts, and status; configuration records also include a security score. `GET /api/scan/history/{scan_id}` returns configuration scan details. Runtime history records have a separate runtime-results endpoint.

The analytics API (`GET /api/scan/statistics`) computes totals, average score, severity distribution, Network Function finding counts, score trend, frequent rules, and recent activity from SQLite records. The rule catalog (`GET /api/scan/rules`) lists only implemented generic and Open5GS-specific checks. Finding remediation statuses can be persisted with `PUT /api/scan/history/{scan_id}/findings/{rule_id}/status`.

The Sample Configurations page reads its catalog from `frontend/public/sample_configs/manifest.json`; each listed YAML/JSON file is tested against the existing parser and analyzer rules. Clean samples mean only that no currently implemented rule matched.

### Network Alpha runtime environment

The **5G Test Environments** page displays live Network Alpha service state, service health, latest runtime assessment and saved findings. The API uses fixed Docker Compose operations; it does not accept or execute arbitrary shell commands. On Windows with Docker available in WSL, the backend invokes Docker Compose through the configured WSL distribution. Keep the environment isolated and use only for authorized local testing.

- `GET /api/environments/alpha` retrieves live status and service details.
- `POST /api/environments/alpha/start` starts the configured Compose project.
- `POST /api/environments/alpha/stop` stops that project without removing its data.
- `POST /api/environments/alpha/assessments` runs and stores a runtime assessment.
- `GET /api/environments/alpha/assessments` lists saved assessments; `GET /api/environments/alpha/assessments/{assessment_id}` retrieves a result. The Alpha status response includes the latest assessment summary.
- `GET /api/environments/statistics` returns live status and persisted runtime/configuration finding aggregates.

Runtime findings are distinct from informational observations and from YAML/JSON findings. The assessment checks expected service availability/health, published host ports, Docker network isolation, and the result of the configured SBI TLS health checks. It does not claim to test UE access, perform broad port scans, or infer NAS null algorithms from network traffic. Runtime assessments are stored in the same SQLite database as configuration history, in separate runtime tables.

For disposable integration testing, `SUSIGNAL_DB_PATH` may point the backend to a separate SQLite file; leave the normal configured database untouched.

---

## 8. Current Implementation Status

| Feature / Component | Status | Description |
| :--- | :--- | :--- |
| **Backend API Gateway** | Complete | FastAPI with CORS, health-check (`/api/health`), configuration routes, and runtime environment routes. |
| **Config Parsers** | Complete | Safe deserialization for YAML and JSON with format validation. |
| **Security Rule Engine** | Complete (Starter) | Modular rule structure with starter rules (NEA0, plaintext SBI, 0.0.0.0 bind, mTLS). |
| **Open5GS YAML Rules** | Partial | Native Open5GS structure analysis includes null NAS algorithms and explicit HTTP SBI client URIs. |
| **Severity Classification** | Complete | Risk levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and health score calculator. |
| **SQLite Persistence** | Complete | Stores configuration scans/findings and separate runtime assessments/records; merges both assessment types in history. |
| **Frontend Dashboard** | Complete | Active vanilla-JavaScript dashboard includes configuration analytics, Network Alpha runtime statistics/charts, findings, history, scan comparison, rules, remediation, reports, and topology. |
| **API Client Layer** | Complete | Centralized client for health, configuration scan APIs, and Network Alpha status/lifecycle/runtime APIs. |
| **Network Alpha Runtime Integration** | Initial | Controlled start/stop, live service health/status, persisted runtime assessments, and runtime results; assessment scope is limited to checks documented above. |
| **Sample Configuration Library** | Complete | 20 parser- and analyzer-validated samples across secure, individual weakness, multiple weakness, and real Open5GS v2.8.0 categories. |

---

## 9. Open5GS & free5GC Integration Status

SUSignal can analyze uploaded native Open5GS YAML configurations using dedicated rules selected by the Open5GS configuration structure. Current Open5GS checks include null NAS integrity/ciphering algorithms and explicitly configured HTTP SBI client URIs. Open5GS v2.8 selects the client transport from each URI scheme; an `http://` URI therefore does not use TLS.

The existing upload endpoint and analyzer response format are unchanged. Runtime management currently supports the isolated Network Alpha Compose environment; free5GC integration remains future work.

### How the Architecture Accommodates Future Integrations:
- The core scanner requires **no direct dependency or deployment** of Open5GS or free5GC.
- Network Alpha's runtime manager is isolated from configuration parsing and scanning.
- Future adapters can read platform-specific configuration sources; the existing parser and analyzer continue to process uploaded configuration dictionaries.
