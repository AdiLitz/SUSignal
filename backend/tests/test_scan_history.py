import asyncio
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app.database.db as database
from app.routes.scanner import (
    RemediationStatusUpdate,
    get_scan_history,
    get_scan_history_detail,
    list_security_rules,
    scan_statistics,
    set_remediation_status,
)


class ScanHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "test.db"
        self.db_file_patch = patch.object(database, "DB_FILE", str(self.database_path))
        self.db_file_patch.start()
        self.addCleanup(self.db_file_patch.stop)
        self.addCleanup(self.temp_dir.cleanup)
        database.init_db()

    def save_scan(self, scan_id, filename, network_function, score, findings):
        counts = {
            "critical": sum(item["severity"] == "CRITICAL" for item in findings),
            "high": sum(item["severity"] == "HIGH" for item in findings),
            "medium": sum(item["severity"] == "MEDIUM" for item in findings),
            "low": sum(item["severity"] == "LOW" for item in findings),
        }
        summary = {
            **counts,
            "network_function": network_function,
            "security_score": score,
            "total_findings": len(findings),
            "total_rules_checked": 4,
            "status": "VULNERABILITIES_FOUND" if findings else "CLEAN",
        }
        database.save_scan_record(
            scan_id=scan_id,
            filename=filename,
            file_type="yaml",
            summary=summary,
            findings=findings,
        )

    def test_history_statistics_and_pagination_use_persisted_summaries(self):
        self.save_scan(
            "scan-amf",
            "amf.yaml",
            "AMF",
            70,
            [
                {
                    "rule_id": "OPEN5GS-AMF-001",
                    "title": "NIA0",
                    "target_nf": "AMF",
                    "severity": "HIGH",
                    "category": "Cryptographic Protection",
                    "description": "Null integrity",
                    "remediation": "Remove NIA0",
                },
                {
                    "rule_id": "OPEN5GS-SBI-001",
                    "title": "HTTP SBI",
                    "target_nf": "ALL",
                    "severity": "MEDIUM",
                    "category": "Transport Security",
                    "description": "HTTP client URI",
                    "remediation": "Use HTTPS",
                },
            ],
        )
        self.save_scan(
            "scan-smf",
            "smf.yaml",
            "SMF",
            80,
            [{
                "rule_id": "5GS-SBI-002",
                "title": "HTTP SBI",
                "target_nf": "ALL",
                "severity": "CRITICAL",
                "category": "Transport Security",
                "description": "HTTP scheme",
                "remediation": "Use HTTPS",
            }],
        )

        page = asyncio.run(get_scan_history(limit=1, offset=1))
        self.assertEqual(page["total"], 2)
        self.assertEqual(page["count"], 1)
        self.assertEqual(page["scans"][0]["scan_id"], "scan-amf")
        self.assertEqual(page["scans"][0]["network_function"], "AMF")
        self.assertEqual(page["scans"][0]["security_score"], 70)

        filtered_page = asyncio.run(get_scan_history(
            search="smf",
            network_function="SMF",
            severity="CRITICAL",
            sort="score-asc",
        ))
        self.assertEqual(filtered_page["total"], 1)
        self.assertEqual(filtered_page["scans"][0]["scan_id"], "scan-smf")

        stats = asyncio.run(scan_statistics())
        self.assertEqual(stats["stats"]["total_scans"], 2)
        self.assertEqual(stats["stats"]["average_security_score"], 75)
        self.assertEqual(stats["stats"]["total_vulnerabilities"], 3)
        self.assertEqual(stats["stats"]["network_functions_analyzed"], 2)
        self.assertEqual(stats["severity_distribution"]["critical"], 1)
        self.assertEqual(stats["severity_distribution"]["high"], 1)
        self.assertEqual(stats["severity_distribution"]["medium"], 1)
        nf_counts = {
            item["network_function"]: item["count"]
            for item in stats["vulnerabilities_by_network_function"]
        }
        self.assertEqual(nf_counts["AMF"], 2)
        self.assertEqual(nf_counts["SMF"], 1)
        self.assertEqual(stats["frequent_rules"][0]["count"], 1)

    def test_scan_details_and_remediation_status_are_persisted(self):
        self.save_scan(
            "scan-amf",
            "amf.yaml",
            "AMF",
            70,
            [{
                "rule_id": "OPEN5GS-AMF-001",
                "title": "NIA0",
                "target_nf": "AMF",
                "severity": "HIGH",
                "category": "Cryptographic Protection",
                "description": "Null integrity",
                "remediation": "Remove NIA0",
            }],
        )

        response = asyncio.run(set_remediation_status(
            "scan-amf",
            "OPEN5GS-AMF-001",
            RemediationStatusUpdate(target_nf="AMF", status="FIXED"),
        ))
        self.assertEqual(response["remediation"]["status"], "FIXED")

        detail = asyncio.run(get_scan_history_detail("scan-amf"))
        self.assertEqual(detail["status"], "success")
        self.assertEqual(detail["scan_status"], "COMPLETED")
        self.assertTrue(detail["findings_available"])
        self.assertEqual(detail["findings"][0]["target_nf"], "AMF")
        self.assertEqual(detail["findings"][0]["remediation_status"], "FIXED")

    def test_empty_statistics_and_rule_catalog(self):
        stats = asyncio.run(scan_statistics())
        self.assertEqual(stats["stats"]["total_scans"], 0)
        self.assertIsNone(stats["stats"]["average_security_score"])
        self.assertEqual(stats["stats"]["total_vulnerabilities"], 0)
        self.assertEqual(stats["stats"]["network_functions_analyzed"], 0)

        catalog = asyncio.run(list_security_rules())
        self.assertEqual(len(catalog["rules"]), 7)
        self.assertEqual(
            {rule["scope"] for rule in catalog["rules"]},
            {"Generic", "Open5GS-specific"},
        )

    def test_init_db_migrates_existing_findings_table(self):
        legacy_path = Path(self.temp_dir.name) / "legacy.db"
        with patch.object(database, "DB_FILE", str(legacy_path)):
            conn = sqlite3.connect(legacy_path)
            try:
                conn.execute("""
                    CREATE TABLE scans (
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
                conn.execute("""
                    CREATE TABLE findings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT NOT NULL,
                        rule_id TEXT NOT NULL,
                        title TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        category TEXT,
                        description TEXT,
                        remediation TEXT
                    )
                """)
                conn.commit()
            finally:
                conn.close()

            database.init_db()
            conn = sqlite3.connect(legacy_path)
            try:
                columns = {
                    row[1] for row in conn.execute("PRAGMA table_info(findings)")
                }
            finally:
                conn.close()
        self.assertIn("target_nf", columns)


if __name__ == "__main__":
    unittest.main()
