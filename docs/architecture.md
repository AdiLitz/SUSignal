# SUSignal – Architecture & Design Specification

## 1. Executive Summary

**SUSignal** is a modular cybersecurity scanner engineered to identify security misconfigurations across 5G Core Network Functions (NFs) such as AMF, SMF, UPF, NRF, AUSF, and UDM. 

The architecture is built for strict separation of concerns, allowing four developers to simultaneously build modules in parallel without code collisions or tight dependencies.

---

## 2. High-Level Architecture

```
+-------------------------------------------------------------------------+
|                           FRONTEND LAYER                                |
| (Vanilla JavaScript + Vite + CSS + Central API Client)                  |
+------------------------------------+------------------------------------+
                                     |  HTTP REST (JSON / Multipart)
                                     v
+------------------------------------+------------------------------------+
|                         BACKEND API LAYER                               |
|                         (FastAPI - main.py)                             |
+------------------------------------+------------------------------------+
                                     |
                                     v
+------------------------------------+------------------------------------+
|                      SCANNER INGESTION & PIPELINE                       |
|                                                                         |
| [Upload: routes/scanner.py]   [Environment: routes/environments.py]     |
|             |                              |                            |
|             v                              v                            |
| [parser.py -> analyzer.py]    [Open5GS Alpha Compose manager]            |
|             |                 [runtime_assessment.py]                    |
|             |                              |                            |
|             +--------------+---------------+                            |
|                            v                                            |
|             [SQLite: configuration and runtime records]                 |
|                                                                         |
+------------------------------------+------------------------------------+
                                     |
                                     v
+------------------------------------+------------------------------------+
|                         PERSISTENCE LAYER                               |
|                     (SQLite - database/db.py)                           |
+-------------------------------------------------------------------------+
```

---

## 3. Module Responsibilities

| Module / File | Primary Responsibility | Developer Ownership |
| :--- | :--- | :--- |
| `backend/app/main.py` | FastAPI app lifecycle, middleware, route aggregation, `/api/health`. | Lead / Integration Dev |
| `backend/app/routes/scanner.py` | Upload, paginated history, scan details, analytics, rule catalog, and remediation APIs. | Backend Dev A |
| `backend/app/routes/environments.py` | Network Alpha status, fixed lifecycle operations, runtime assessment, and runtime result APIs. | Lead / Integration Dev |
| `backend/app/scanner/parser.py` | Safe deserialization of YAML & JSON into standard Python dictionaries, NF heuristics. | Backend Dev A |
| `backend/app/scanner/analyzer.py` | Orchestrates analysis: matches applicable rules, calculates score, builds summary. | Backend Dev B |
| `backend/app/scanner/rules.py` | Standalone rule definitions (target NF, category, logic, remediation guidelines). | Backend Dev B |
| `backend/app/scanner/risk.py` | Severity enum (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), weighting factors, visual badges. | Backend Dev B |
| `backend/app/database/db.py` | SQLite schema migration, configuration scan history, separate runtime assessments/records, and merged history. | Backend Dev A |
| `backend/app/integrations/open5gs_alpha.py` | Fixed Docker Compose operations for the local Network Alpha project; API callers cannot submit arbitrary commands. | Lead / Integration Dev |
| `backend/app/scanner/runtime_assessment.py` | Assesses expected service state/health, published ports, network isolation and SBI TLS healthcheck results; keeps runtime findings separate from configuration findings. | Lead / Integration Dev |
| `frontend/index.html`, `frontend/src/app.js` | Active vanilla-JavaScript dashboard, sample library, analytics, findings, history, comparison, and reports. | Frontend Devs (C & D) |
| `frontend/src/services/api.js` | Central client for backend health, upload, history, analytics, details, rules, and remediation. | Frontend Devs (C & D) |
| `frontend/public/sample_configs/` | Manifest and downloadable sample configurations validated by the scanner tests. | Frontend Devs (C & D) |

---

## 4. Network Alpha Runtime Integration and Future Core Support

SUSignal manages the existing isolated Network Alpha Compose environment through fixed status/start/stop operations. The browser does not connect to Docker and cannot submit shell commands. On Windows, the manager invokes the configured WSL distribution when the Docker CLI is unavailable natively.

Runtime checks cover the configured service set and health states, published host ports, Docker network isolation, and the result of the environment's SBI TLS health checks. Findings are persisted in runtime-specific tables; informational observations are not counted as security findings. These checks do not inspect NAS algorithm negotiation or assert UE/service functionality.

The uploaded YAML/JSON pipeline remains independent. Future Open5GS or free5GC configuration adapters may normalize source-specific configuration, but they must not be coupled to runtime assessment or require a live core for ordinary configuration uploads.

---

## 5. Team Work Breakdown (4-Developer Matrix)

```
   Developer 1 (API & Storage)    <--->    Developer 2 (Rules & Engine)
   - routes/scanner.py                    - scanner/rules.py
   - scanner/parser.py                    - scanner/analyzer.py
   - database/db.py                       - scanner/risk.py
   
   Developer 3 (Frontend Core & UI) <->   Developer 4 (Data Viz & UX)
   - index.html / app.js                  - charts & metrics
   - services/api.js                      - sample config library
```
