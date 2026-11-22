# SUSignal API Contract

This document defines the formal API specifications for SUSignal, governing communication between the Frontend application, Backend services, and external automated integration pipelines.

---

## 1. General Principles

- **Base URL:** `http://localhost:8000/api`
- **Data Exchange Format:** `application/json` (except file uploads which use `multipart/form-data`)
- **Authentication:** None for initial local development / hackathon phase.
- **CORS Support:** Permitted for standard local frontend origins (`http://localhost:5173`, `http://127.0.0.1:5173`, `http://localhost:3000`).

---

## 2. Endpoints

### 2.1 Health Check

Verifies backend server readiness and sub-module status.

- **Route:** `GET /api/health`
- **Headers:** `Accept: application/json`
- **Response Code:** `200 OK`

#### Response Body:
```json
{
  "status": "healthy",
  "service": "SUSignal API",
  "version": "0.1.0",
  "supported_formats": ["YAML", "JSON"],
  "modules": {
    "scanner": "online",
    "database": "online",
    "integrations": "configured",
    "runtime_environments": "configured"
  }
}
```

---

### 2.2 Upload & Scan Configuration

Uploads a 5G Network Function configuration file (YAML or JSON), executes security rule evaluation, logs the scan to SQLite, and returns findings.

- **Route:** `POST /api/scan/upload`
- **Content-Type:** `multipart/form-data`
- **Parameters:**
  - `file` (*required*, binary): The YAML (`.yaml`, `.yml`) or JSON (`.json`) configuration file.
- **Max File Size:** `5 MB`

#### Success Response (`200 OK`):
```json
{
  "status": "success",
  "scan_id": "8b5128cf-2401-4be5-a134-8c8fb5028405",
  "assessment_id": "8b5128cf-2401-4be5-a134-8c8fb5028405",
  "assessment_type": "configuration",
  "filename": "amf_vulnerable.yaml",
  "file_type": "yaml",
  "summary": {
    "network_function": "AMF",
    "total_rules_checked": 3,
    "total_findings": 3,
    "critical": 1,
    "high": 1,
    "medium": 1,
    "low": 0,
    "security_score": 58,
    "status": "VULNERABILITIES_FOUND"
  },
  "findings": [
    {
      "rule_id": "5GS-CRYP-001",
      "title": "Null Ciphering Enabled (NEA0)",
      "target_nf": "AMF",
      "severity": "CRITICAL",
      "category": "Cryptographic Protection",
      "description": "The AMF allows or prioritizes NEA0 (null ciphering), allowing non-emergency NAS traffic to be transmitted in plaintext without confidentiality protection.",
      "remediation": "Remove NEA0 from ciphering_order in the security block. Enforce NEA1 (128-EEA1/SNOW 3G), NEA2 (128-EEA2/AES), or NEA3 (128-EEA3/ZUC)."
    },
    {
      "rule_id": "5GS-SBI-002",
      "title": "Insecure HTTP Scheme on Service Based Interface",
      "target_nf": "ALL",
      "severity": "HIGH",
      "category": "Transport Security",
      "description": "Network Function SBI endpoints are configured with unencrypted 'http' scheme instead of 'https', exposing inter-NF API traffic to sniffing and MITM attacks (3GPP TS 33.501 Section 13.1).",
      "remediation": "Change sbi.scheme to 'https' and supply valid TLS server certificates, private keys, and trusted CA bundles."
    },
    {
      "rule_id": "5GS-NET-003",
      "title": "Wildcard Service Address Binding (0.0.0.0)",
      "target_nf": "ALL",
      "severity": "MEDIUM",
      "category": "Network Hardening",
      "description": "The Network Function binds service listening interfaces to wildcard 0.0.0.0, potentially exposing control plane interfaces across unintended networks or management planes.",
      "remediation": "Bind service endpoints to specific dedicated internal network slice interfaces or isolated loopback addresses."
    }
  ]
}
```

#### Error Responses:

- **400 Bad Request** (Unsupported file extension, empty file, or parsing syntax error):
```json
{
  "detail": "Unsupported file format for 'document.pdf'. Only YAML (.yaml, .yml) and JSON (.json) files are permitted."
}
```
```json
{
  "detail": "Configuration syntax error: Failed to parse file as valid YAML or JSON: YAML error: while parsing a block mapping..."
}
```

- **413 Payload Too Large** (File exceeds 5MB):
```json
{
  "detail": "Configuration file exceeds maximum allowed size of 5MB."
}
```

---

### 2.3 Scan History

Fetches paginated scan summaries from SQLite. Filtering and sorting are performed against persisted records.

- **Route:** `GET /api/scan/history`
- **Query parameters:** `limit` (1–500, default 100), `offset` (default 0), `search` (filename), `network_function`, `severity` (`CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`), and `sort` (`date-asc`, `date-desc`, `score-asc`, or `score-desc`).
- **Response Code:** `200 OK`

#### Response Body:
```json
{
  "status": "success",
  "count": 1,
  "total": 1,
  "limit": 100,
  "offset": 0,
  "scans": [
    {
      "scan_id": "8b5128cf-2401-4be5-a134-8c8fb5028405",
      "filename": "amf_vulnerable.yaml",
      "file_type": "yaml",
      "scanned_at": "2026-11-21T04:38:00.000Z",
      "network_function": "AMF",
      "security_score": 58,
      "critical_count": 1,
      "high_count": 1,
      "medium_count": 1,
      "low_count": 0,
      "total_findings": 3,
      "status": "COMPLETED",
      "result_status": "VULNERABILITIES_FOUND"
    }
  ]
}
```

### 2.4 Saved Scan Details

Returns the stored summary and finding records for a scan.

- **Route:** `GET /api/scan/history/{scan_id}`
- **Response:** Includes top-level `status: "success"`, scan metadata, `summary`, `findings`, and `findings_available`. The persisted completion state is returned as `scan_status` (for example, `COMPLETED`). If legacy finding details are incomplete, `findings_available` is false.

### 2.5 Dashboard Statistics

Calculates aggregate statistics and charts from persisted scans and findings.

- **Route:** `GET /api/scan/statistics`
- **Response:** Includes total scans, average security score (null when no scores exist), total vulnerabilities, distinct recognized Network Functions, severity totals, findings by NF, score trend (latest 100 scored scans), most frequent rules, and recent scans.

### 2.6 Implemented Rule Catalog

Returns only rules registered in the generic scanner and Open5GS scanner.

- **Route:** `GET /api/scan/rules`
- **Response:** Rule metadata includes ID, title, target NF, severity, category, description, remediation, and implementation scope (`Generic` or `Open5GS-specific`).

### 2.7 Remediation Status

Updates a finding status for one scan. Status values are `PENDING`, `FIXED`, and `ACCEPTED_RISK`.

- **Route:** `PUT /api/scan/history/{scan_id}/findings/{rule_id}/status`
- **Request body:**
```json
{
  "target_nf": "AMF",
  "status": "FIXED"
}
```
- **Persistence:** Statuses are stored per scan, rule ID, and target NF. A scan comparison does not automatically update these statuses.

### 2.8 Network Alpha status and lifecycle

These routes operate only on the configured Network Alpha Compose project. They do not accept shell commands, service names, or Compose paths from API callers.

- `GET /api/environments` returns the managed environment list.
- `GET /api/environments/alpha` returns live service state, health, host-published ports, network isolation status, and the latest assessment summary.
- `POST /api/environments/alpha/start` starts the configured project.
- `POST /api/environments/alpha/stop` stops the configured project without deleting its volumes.
- `GET /api/environments/statistics` returns current network status plus persisted runtime assessment/finding aggregates and configuration-vs-runtime totals.

Lifecycle responses contain `status: "success"` and an `environment` object with the environment identity, status, configured Network Function count, running/healthy service counts, per-service states, published ports, and internal network status. Docker/WSL failures return HTTP `503` with a descriptive `detail`.

### 2.9 Network Alpha runtime assessments

- `POST /api/environments/alpha/assessments` runs and persists an assessment.
- `GET /api/environments/alpha/assessments?limit=20` lists saved assessment summaries.
- `GET /api/environments/alpha/assessments/{assessment_id}` returns one assessment, including `summary`, `environment_status`, `findings`, and `observations`.

Runtime findings assess expected service availability and configured healthchecks (including supporting services), host-published service ports, and whether Docker reports the core network as internal. TLS observations are based on the configured SBI healthcheck's HTTPS/mTLS result. Informational observations are separate from security findings and do not increase finding totals. This is not a general port scanner and does not infer NAS algorithm negotiation.

Runtime assessment persistence uses separate SQLite tables and is tagged `assessment_type: "runtime"` in merged history. Existing configuration scans remain tagged `assessment_type: "configuration"` and retain their existing upload and result contracts.
