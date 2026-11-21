# 5G Sentinel – Architecture & Design Specification

## 1. Executive Summary

**5G Sentinel** is a modular cybersecurity scanner engineered to identify security misconfigurations across 5G Core Network Functions (NFs) such as AMF, SMF, UPF, NRF, AUSF, and UDM. 

The architecture is built for strict separation of concerns, allowing four developers to simultaneously build modules in parallel without code collisions or tight dependencies.

---

## 2. High-Level Architecture

```
+-------------------------------------------------------------------------+
|                           FRONTEND LAYER                                |
|   (React.js + Vite + Tailwind CSS + Recharts + Central API Client)      |
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
|   [Upload Endpoint]       [Future: Open5GS]      [Future: free5GC]      |
|   (routes/scanner.py)    (integrations/)        (integrations/)         |
|            \                     |                     /                |
|             +--------------------+--------------------+                 |
|                                  |                                      |
|                                  v                                      |
|                       [parser.py: YAML / JSON]                          |
|                                  |                                      |
|                                  v                                      |
|                        [analyzer.py (Orchestrator)]                     |
|                               /     \                                   |
|                              v       v                                  |
|                   [rules.py Engine]  [risk.py Classification]           |
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
| `backend/app/routes/scanner.py` | API endpoints (`/upload`, `/history`), input validation, HTTP error codes. | Backend Dev A |
| `backend/app/scanner/parser.py` | Safe deserialization of YAML & JSON into standard Python dictionaries, NF heuristics. | Backend Dev A |
| `backend/app/scanner/analyzer.py` | Orchestrates analysis: matches applicable rules, calculates score, builds summary. | Backend Dev B |
| `backend/app/scanner/rules.py` | Standalone rule definitions (target NF, category, logic, remediation guidelines). | Backend Dev B |
| `backend/app/scanner/risk.py` | Severity enum (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), weighting factors, visual badges. | Backend Dev B |
| `backend/app/database/db.py` | SQLite connection, table schema migrations, scan history logging. | Backend Dev A |
| `backend/app/integrations/` | Abstract adapters reserved for Phase 2 Open5GS and free5GC imports. | Future Scope |
| `frontend/src/` | Cybersecurity dashboard, file uploader, findings table, charts, API client. | Frontend Devs (C & D) |

---

## 4. Future Open5GS and free5GC Integration Strategy

A primary long-term capability of 5G Sentinel is inspecting configurations directly from live or lab 5G Core implementations (Open5GS and free5GC).

### Key Architectural Guidelines:
1. **Zero Runtime Dependency:** The core scanner must never import Open5GS or free5GC binaries or require a live 5G Core installation to operate.
2. **Adapter Pattern:** The `backend/app/integrations/` directory provides `Base5GCoreAdapter`. Future adapters (`Open5GSAdapter`, `Free5GCAdapter`) will parse vendor-specific configuration trees and normalize them into standard dictionaries.
3. **Unified Analysis Pipeline:** Regardless of whether configuration originated from a manual web upload, an Open5GS YAML file, or a free5GC cluster, the parsed dictionary is evaluated by the exact same `analyzer.analyze_configuration()` engine.

---

## 5. Team Work Breakdown (4-Developer Matrix)

```
   Developer 1 (API & Storage)    <--->    Developer 2 (Rules & Engine)
   - routes/scanner.py                    - scanner/rules.py
   - scanner/parser.py                    - scanner/analyzer.py
   - database/db.py                       - scanner/risk.py
   
   Developer 3 (Frontend Core & UI) <->   Developer 4 (Data Viz & UX)
   - App.jsx / layout                     - charts & metrics (Recharts)
   - components/UploadSection.jsx         - components/ScanResults.jsx
   - services/api.js                      - sample config presets
```
