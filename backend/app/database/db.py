import sqlite3
import json
import os
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

# Database file location relative to backend app
DB_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.environ.get(
    "SUSIGNAL_DB_PATH",
    os.path.join(DB_DIR, "susignal.db"),
)


def get_db_connection() -> sqlite3.Connection:
    """
    Establish and return a connection to the SQLite database.
    Row factory is set to sqlite3.Row for dict-like access.
    """
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """
    Initialize SQLite database tables for scans and findings.
    Keeps schema simple, robust, and extensible for future needs.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        # Scans table: records file metadata, timestamp, summary stats
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE NOT NULL,
                filename TEXT NOT NULL,
                file_type TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                total_findings INTEGER DEFAULT 0,
                status TEXT NOT NULL,
                summary_json TEXT
            )
        """)

        # Findings table: records individual misconfigurations linked to scans
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                target_nf TEXT,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT,
                description TEXT,
                remediation TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id) ON DELETE CASCADE
            )
        """)

        finding_columns = {
            row["name"] for row in cursor.execute("PRAGMA table_info(findings)")
        }
        if "target_nf" not in finding_columns:
            cursor.execute("ALTER TABLE findings ADD COLUMN target_nf TEXT")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS remediation_statuses (
                scan_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                target_nf TEXT NOT NULL,
                status TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (scan_id, rule_id, target_nf)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS runtime_assessments (
                assessment_id TEXT PRIMARY KEY,
                network_id TEXT NOT NULL,
                network_name TEXT NOT NULL,
                assessed_at TEXT NOT NULL,
                assessment_status TEXT NOT NULL,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                total_findings INTEGER DEFAULT 0,
                total_observations INTEGER DEFAULT 0,
                summary_json TEXT NOT NULL,
                environment_status_json TEXT NOT NULL
            )
        """)
        runtime_columns = {
            row["name"]
            for row in cursor.execute("PRAGMA table_info(runtime_assessments)")
        }
        if "network_id" not in runtime_columns:
            cursor.execute(
                "ALTER TABLE runtime_assessments "
                "ADD COLUMN network_id TEXT NOT NULL DEFAULT 'alpha'"
            )
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS runtime_assessment_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id TEXT NOT NULL,
                record_type TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                component TEXT,
                description TEXT,
                evidence TEXT,
                remediation TEXT,
                FOREIGN KEY (assessment_id)
                    REFERENCES runtime_assessments (assessment_id)
                    ON DELETE CASCADE
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_runtime_assessments_date
            ON runtime_assessments (assessed_at)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_runtime_records_assessment
            ON runtime_assessment_records (assessment_id, id)
        """)

        conn.commit()
    finally:
        conn.close()


def save_scan_record(
    scan_id: str,
    filename: str,
    file_type: str,
    summary: Dict[str, Any],
    findings: List[Dict[str, Any]],
    status: str = "COMPLETED"
) -> None:
    """
    Save a completed scan summary and its findings into SQLite.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        scanned_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        cursor.execute("""
            INSERT OR REPLACE INTO scans (
                scan_id, filename, file_type, scanned_at,
                critical_count, high_count, medium_count, low_count,
                total_findings, status, summary_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            filename,
            file_type,
            scanned_at,
            summary.get("critical", 0),
            summary.get("high", 0),
            summary.get("medium", 0),
            summary.get("low", 0),
            summary.get("total_findings", len(findings)),
            status,
            json.dumps(summary)
        ))

        # Insert findings
        for finding in findings:
            cursor.execute("""
                INSERT INTO findings (
                    scan_id, rule_id, target_nf, title, severity, category, description, remediation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                finding.get("rule_id", "UNKNOWN"),
                finding.get("target_nf", ""),
                finding.get("title", ""),
                finding.get("severity", "LOW"),
                finding.get("category", "General"),
                finding.get("description", ""),
                finding.get("remediation", "")
            ))

        conn.commit()
    finally:
        conn.close()


def _summary_from_json(value: Optional[str]) -> Dict[str, Any]:
    if not value:
        return {}
    try:
        summary = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return {}
    return summary if isinstance(summary, dict) else {}


def _scan_payload(row: sqlite3.Row) -> Dict[str, Any]:
    summary = _summary_from_json(row["summary_json"])
    return {
        "scan_id": row["scan_id"],
        "assessment_id": row["scan_id"],
        "assessment_type": "configuration",
        "filename": row["filename"],
        "file_type": row["file_type"],
        "scanned_at": row["scanned_at"],
        "network_function": summary.get("network_function"),
        "security_score": summary.get("security_score"),
        "total_findings": row["total_findings"] or summary.get("total_findings", 0),
        "critical_count": row["critical_count"] or summary.get("critical", 0),
        "high_count": row["high_count"] or summary.get("high", 0),
        "medium_count": row["medium_count"] or summary.get("medium", 0),
        "low_count": row["low_count"] or summary.get("low", 0),
        "status": row["status"],
        "result_status": summary.get("status"),
    }


def _runtime_history_payload(row: sqlite3.Row) -> Dict[str, Any]:
    summary = _summary_from_json(row["summary_json"])
    return {
        "scan_id": row["assessment_id"],
        "assessment_id": row["assessment_id"],
        "assessment_type": "runtime",
        "network_id": row["network_id"],
        "filename": f"{row['network_name']} runtime assessment",
        "file_type": "runtime",
        "scanned_at": row["assessed_at"],
        "network_function": row["network_name"],
        "security_score": None,
        "total_findings": int(row["total_findings"] or 0),
        "critical_count": int(row["critical_count"] or 0),
        "high_count": int(row["high_count"] or 0),
        "medium_count": int(row["medium_count"] or 0),
        "low_count": int(row["low_count"] or 0),
        "status": row["assessment_status"],
        "result_status": summary.get("status"),
    }


def get_recent_scans(limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    """
    Retrieve a page of recently executed scans with summary fields.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT scan_id, filename, file_type, scanned_at,
                   critical_count, high_count, medium_count, low_count,
                   total_findings, status, summary_json
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            OFFSET ?
        """, (limit, offset))
        rows = cursor.fetchall()
        return [_scan_payload(row) for row in rows]
    finally:
        conn.close()


def search_scan_history(
    limit: int = 100,
    offset: int = 0,
    search: str = "",
    network_function: str = "",
    severity: str = "",
    sort: str = "date-desc"
) -> Dict[str, Any]:
    severity_columns = {
        "CRITICAL": "critical_count",
        "HIGH": "high_count",
        "MEDIUM": "medium_count",
        "LOW": "low_count",
    }
    conn = get_db_connection()
    try:
        rows = conn.execute("""
            SELECT scan_id, filename, file_type, scanned_at,
                   critical_count, high_count, medium_count, low_count,
                   total_findings, status, summary_json
            FROM scans
            ORDER BY id
        """).fetchall()
        scans = [_scan_payload(row) for row in rows]
        runtime_rows = conn.execute("""
            SELECT assessment_id, network_id, network_name, assessed_at,
                   assessment_status, critical_count, high_count, medium_count, low_count,
                   total_findings, summary_json
            FROM runtime_assessments
            ORDER BY assessed_at DESC
        """).fetchall()
        scans.extend(_runtime_history_payload(row) for row in runtime_rows)
        normalized_search = search.strip().casefold()
        normalized_nf = network_function.strip().upper()
        normalized_severity = severity.strip().upper()
        if normalized_severity not in severity_columns and normalized_severity:
            raise ValueError("Severity must be CRITICAL, HIGH, MEDIUM, or LOW.")

        if normalized_search:
            scans = [
                scan for scan in scans
                if normalized_search in scan["filename"].casefold()
            ]
        if normalized_nf:
            scans = [
                scan for scan in scans
                if scan["assessment_type"] == "configuration"
                and (scan["network_function"] or "").upper() == normalized_nf
            ]
        if normalized_severity:
            count_key = severity_columns[normalized_severity]
            scans = [
                scan for scan in scans
                if int(scan[count_key] or 0) > 0
            ]

        if sort == "date-asc":
            scans.sort(key=lambda scan: scan["scanned_at"] or "")
        elif sort == "score-asc":
            scans.sort(key=lambda scan: (
                scan["security_score"] is None,
                float(scan["security_score"] or 0),
            ))
        elif sort == "score-desc":
            scans.sort(key=lambda scan: (
                scan["security_score"] is None,
                -float(scan["security_score"] or 0),
            ))
        elif sort == "date-desc":
            scans.sort(key=lambda scan: scan["scanned_at"] or "", reverse=True)
        else:
            raise ValueError("Sort must be date-asc, date-desc, score-asc, or score-desc.")

        total = len(scans)
        return {
            "total": total,
            "scans": scans[offset:offset + limit],
        }
    finally:
        conn.close()


def get_scan_count() -> int:
    conn = get_db_connection()
    try:
        row = conn.execute("SELECT COUNT(*) AS count FROM scans").fetchone()
        return int(row["count"])
    finally:
        conn.close()


def get_scan_details(scan_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        scan_row = conn.execute("""
            SELECT scan_id, filename, file_type, scanned_at,
                   critical_count, high_count, medium_count, low_count,
                   total_findings, status, summary_json
            FROM scans
            WHERE scan_id = ?
        """, (scan_id,)).fetchone()
        if scan_row is None:
            return None

        scan = _scan_payload(scan_row)
        summary = _summary_from_json(scan_row["summary_json"])
        finding_rows = conn.execute("""
            SELECT rule_id, target_nf, title, severity, category, description, remediation
            FROM findings
            WHERE scan_id = ?
            ORDER BY id
        """, (scan_id,)).fetchall()
        remediation_rows = conn.execute("""
            SELECT rule_id, target_nf, status
            FROM remediation_statuses
            WHERE scan_id = ?
        """, (scan_id,)).fetchall()
        statuses = {
            (row["rule_id"], row["target_nf"]): row["status"]
            for row in remediation_rows
        }

        findings = []
        for row in finding_rows:
            target_nf = row["target_nf"] or scan["network_function"] or "UNKNOWN"
            findings.append({
                "rule_id": row["rule_id"],
                "target_nf": target_nf,
                "title": row["title"],
                "severity": row["severity"],
                "category": row["category"],
                "description": row["description"],
                "remediation": row["remediation"],
                "remediation_status": statuses.get(
                    (row["rule_id"], target_nf), "PENDING"
                ),
            })

        expected_findings = scan["total_findings"]
        scan.update({
            "summary": summary,
            "findings": findings,
            "findings_available": len(findings) == expected_findings,
        })
        return scan
    finally:
        conn.close()


def get_scan_statistics() -> Dict[str, Any]:
    network_functions = ("AMF", "SMF", "UPF", "NRF", "AUSF", "UDM", "PCF")
    conn = get_db_connection()
    try:
        scan_rows = conn.execute("""
            SELECT scan_id, filename, file_type, scanned_at,
                   critical_count, high_count, medium_count, low_count,
                   total_findings, status, summary_json
            FROM scans
            ORDER BY id
        """).fetchall()
        scans = [_scan_payload(row) for row in scan_rows]
        summaries = [
            _summary_from_json(row["summary_json"])
            for row in scan_rows
        ]
        nf_names = {
            scan["network_function"]
            for scan in scans
            if scan["network_function"] in network_functions
        }
        scores = [
            float(scan["security_score"])
            for scan in scans
            if isinstance(scan["security_score"], (int, float))
        ]

        severity_distribution = {
            "critical": sum(int(scan["critical_count"] or 0) for scan in scans),
            "high": sum(int(scan["high_count"] or 0) for scan in scans),
            "medium": sum(int(scan["medium_count"] or 0) for scan in scans),
            "low": sum(int(scan["low_count"] or 0) for scan in scans),
        }
        total_vulnerabilities = sum(
            int(scan["total_findings"] or 0) for scan in scans
        )

        finding_rows = conn.execute("""
            SELECT f.scan_id, f.rule_id, f.target_nf, f.title, f.severity, f.category
            FROM findings AS f
            JOIN scans AS s ON s.scan_id = f.scan_id
            ORDER BY f.id
        """).fetchall()
        scan_nf_by_id = {
            scan["scan_id"]: scan["network_function"]
            for scan in scans
        }
        nf_counts = {nf: 0 for nf in network_functions}
        rule_counts: Dict[str, Dict[str, Any]] = {}
        for finding in finding_rows:
            scan_nf = scan_nf_by_id.get(finding["scan_id"])
            target_nf = finding["target_nf"]
            effective_nf = (
                target_nf
                if target_nf in network_functions
                else scan_nf
            )
            if effective_nf in nf_counts:
                nf_counts[effective_nf] += 1

            rule_id = finding["rule_id"]
            if rule_id not in rule_counts:
                rule_counts[rule_id] = {
                    "rule_id": rule_id,
                    "title": finding["title"],
                    "severity": finding["severity"],
                    "category": finding["category"],
                    "count": 0,
                }
            rule_counts[rule_id]["count"] += 1

        trend = [
            {
                "scan_id": scan["scan_id"],
                "filename": scan["filename"],
                "network_function": scan["network_function"],
                "scanned_at": scan["scanned_at"],
                "security_score": scan["security_score"],
            }
            for scan in scans
            if isinstance(scan["security_score"], (int, float))
        ]
        trend_limit = 100
        recent_start = max(0, len(scans) - 8)
        recent_scans = [
            {
                **scan,
                "summary": summaries[index],
            }
            for index, scan in enumerate(scans[recent_start:], start=recent_start)
        ]

        return {
            "stats": {
                "total_scans": len(scans),
                "average_security_score": (
                    sum(scores) / len(scores) if scores else None
                ),
                "total_vulnerabilities": total_vulnerabilities,
                "network_functions_analyzed": len(nf_names),
            },
            "severity_distribution": severity_distribution,
            "vulnerabilities_by_network_function": [
                {"network_function": nf, "count": nf_counts[nf]}
                for nf in network_functions
            ],
            "security_score_trend": trend[-trend_limit:],
            "trend_truncated": len(trend) > trend_limit,
            "frequent_rules": sorted(
                rule_counts.values(),
                key=lambda item: (-item["count"], item["rule_id"]),
            )[:10],
            "recent_scans": list(reversed(recent_scans)),
        }
    finally:
        conn.close()


def update_remediation_status(
    scan_id: str,
    rule_id: str,
    target_nf: str,
    status: str
) -> Optional[Dict[str, str]]:
    allowed_statuses = {"PENDING", "FIXED", "ACCEPTED_RISK"}
    normalized_status = status.strip().upper()
    if normalized_status not in allowed_statuses:
        raise ValueError("Status must be PENDING, FIXED, or ACCEPTED_RISK.")

    conn = get_db_connection()
    try:
        finding = conn.execute("""
            SELECT 1
            FROM findings
            WHERE scan_id = ? AND rule_id = ?
              AND (target_nf = ? OR target_nf IS NULL)
            LIMIT 1
        """, (scan_id, rule_id, target_nf)).fetchone()
        if finding is None:
            return None

        updated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        conn.execute("""
            INSERT OR REPLACE INTO remediation_statuses (
                scan_id, rule_id, target_nf, status, updated_at
            ) VALUES (?, ?, ?, ?, ?)
        """, (scan_id, rule_id, target_nf, normalized_status, updated_at))
        conn.commit()
        return {
            "scan_id": scan_id,
            "rule_id": rule_id,
            "target_nf": target_nf,
            "status": normalized_status,
            "updated_at": updated_at,
        }
    finally:
        conn.close()


def save_runtime_assessment(assessment: Dict[str, Any]) -> None:
    summary = assessment["summary"]
    environment_status = assessment["environment_status"]
    conn = get_db_connection()
    try:
        conn.execute("""
            INSERT INTO runtime_assessments (
                assessment_id, network_id, network_name, assessed_at,
                assessment_status, critical_count, high_count,
                medium_count, low_count, total_findings,
                total_observations, summary_json, environment_status_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            assessment["assessment_id"],
            assessment["network_id"],
            assessment["network_name"],
            assessment["assessed_at"],
            assessment["assessment_status"],
            summary.get("critical", 0),
            summary.get("high", 0),
            summary.get("medium", 0),
            summary.get("low", 0),
            summary.get("total_findings", 0),
            summary.get("total_observations", 0),
            json.dumps(summary),
            json.dumps(environment_status),
        ))

        records = [
            *assessment.get("findings", []),
            *assessment.get("observations", []),
        ]
        conn.executemany("""
            INSERT INTO runtime_assessment_records (
                assessment_id, record_type, rule_id, severity, title,
                component, description, evidence, remediation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            (
                assessment["assessment_id"],
                item["record_type"],
                item["rule_id"],
                item["severity"],
                item["title"],
                item.get("component", ""),
                item.get("description", ""),
                item.get("evidence", ""),
                item.get("remediation", ""),
            )
            for item in records
        ])
        conn.commit()
    finally:
        conn.close()


def _runtime_assessment_payload(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "assessment_id": row["assessment_id"],
        "assessment_type": "runtime",
        "network_id": row["network_id"],
        "network_name": row["network_name"],
        "assessed_at": row["assessed_at"],
        "assessment_status": row["assessment_status"],
        "summary": _summary_from_json(row["summary_json"]),
        "environment_status": json.loads(row["environment_status_json"]),
    }


def get_runtime_assessment(assessment_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        row = conn.execute("""
            SELECT assessment_id, network_id, network_name, assessed_at,
                   assessment_status, summary_json, environment_status_json
            FROM runtime_assessments
            WHERE assessment_id = ?
        """, (assessment_id,)).fetchone()
        if row is None:
            return None

        assessment = _runtime_assessment_payload(row)
        records = conn.execute("""
            SELECT record_type, rule_id, severity, title, component,
                   description, evidence, remediation
            FROM runtime_assessment_records
            WHERE assessment_id = ?
            ORDER BY id
        """, (assessment_id,)).fetchall()
        assessment["findings"] = [
            {
                "rule_id": record["rule_id"],
                "severity": record["severity"],
                "title": record["title"],
                "component": record["component"],
                "description": record["description"],
                "evidence": record["evidence"],
                "remediation": record["remediation"],
            }
            for record in records
            if record["record_type"] == "finding"
        ]
        assessment["observations"] = [
            {
                "rule_id": record["rule_id"],
                "severity": record["severity"],
                "title": record["title"],
                "component": record["component"],
                "description": record["description"],
                "evidence": record["evidence"],
            }
            for record in records
            if record["record_type"] == "observation"
        ]
        return assessment
    finally:
        conn.close()


def get_latest_runtime_assessment(
    network_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        if network_id is None:
            row = conn.execute("""
                SELECT assessment_id, network_id, network_name, assessed_at,
                       assessment_status, summary_json, environment_status_json
                FROM runtime_assessments
                ORDER BY assessed_at DESC
                LIMIT 1
            """).fetchone()
        else:
            row = conn.execute("""
                SELECT assessment_id, network_id, network_name, assessed_at,
                       assessment_status, summary_json, environment_status_json
                FROM runtime_assessments
                WHERE network_id = ?
                ORDER BY assessed_at DESC
                LIMIT 1
            """, (network_id,)).fetchone()
        if row is None:
            return None
        return get_runtime_assessment(row["assessment_id"])
    finally:
        conn.close()


def list_runtime_assessments(
    limit: int = 100,
    network_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    try:
        if network_id is None:
            rows = conn.execute("""
                SELECT assessment_id, network_id, network_name, assessed_at,
                       assessment_status, summary_json, environment_status_json
                FROM runtime_assessments
                ORDER BY assessed_at DESC
                LIMIT ?
            """, (limit,)).fetchall()
        else:
            rows = conn.execute("""
                SELECT assessment_id, network_id, network_name, assessed_at,
                       assessment_status, summary_json, environment_status_json
                FROM runtime_assessments
                WHERE network_id = ?
                ORDER BY assessed_at DESC
                LIMIT ?
            """, (network_id, limit)).fetchall()
        return [_runtime_assessment_payload(row) for row in rows]
    finally:
        conn.close()


def get_runtime_assessment_statistics() -> Dict[str, Any]:
    conn = get_db_connection()
    try:
        rows = conn.execute("""
            SELECT network_name, assessment_status, critical_count,
                   high_count, medium_count, low_count, total_findings
            FROM runtime_assessments
        """).fetchall()
        severity = {
            "critical": sum(int(row["critical_count"] or 0) for row in rows),
            "high": sum(int(row["high_count"] or 0) for row in rows),
            "medium": sum(int(row["medium_count"] or 0) for row in rows),
            "low": sum(int(row["low_count"] or 0) for row in rows),
        }
        by_network: Dict[str, int] = {}
        for row in rows:
            by_network[row["network_name"]] = (
                by_network.get(row["network_name"], 0)
                + int(row["total_findings"] or 0)
            )
        return {
            "runtime_assessments_completed": sum(
                row["assessment_status"] == "COMPLETED" for row in rows
            ),
            "total_runtime_findings": sum(
                int(row["total_findings"] or 0) for row in rows
            ),
            "runtime_findings_by_severity": [
                {"severity": key.upper(), "count": value}
                for key, value in severity.items()
            ],
            "runtime_findings_by_network": [
                {"network_name": name, "count": count}
                for name, count in sorted(by_network.items())
            ],
        }
    finally:
        conn.close()
