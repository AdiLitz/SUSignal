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
    "integrations": "ready_for_phase2"
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
    "security_score": 0,
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

Fetches recently recorded scans from the SQLite database.

- **Route:** `GET /api/scan/history`
- **Response Code:** `200 OK`

#### Response Body:
```json
{
  "status": "success",
  "count": 1,
  "scans": [
    {
      "scan_id": "8b5128cf-2401-4be5-a134-8c8fb5028405",
      "filename": "amf_vulnerable.yaml",
      "file_type": "yaml",
      "scanned_at": "2026-11-21T04:38:00.000Z",
      "critical_count": 1,
      "high_count": 1,
      "medium_count": 1,
      "low_count": 0,
      "total_findings": 3,
      "status": "COMPLETED"
    }
  ]
}
```
