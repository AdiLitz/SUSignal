import asyncio
import json
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app.database.db as database
from app.integrations.open5gs_alpha import (
    EXPECTED_SERVICES,
    NETWORK_FUNCTIONS,
    Open5GSAlphaManager,
    Open5GSBetaManager,
)
from app.routes.environments import (
    assess_network_alpha_route,
    assess_network_beta_route,
    get_network_alpha,
    get_network_beta,
    start_network_alpha,
    start_network_beta,
    stop_network_alpha,
    stop_network_beta,
)
from app.scanner.runtime_assessment import assess_network_alpha, assess_network_beta


def healthy_environment(published_ports=None):
    published_ports = published_ports or {}
    services = []
    for service_name in EXPECTED_SERVICES:
        services.append({
            "name": service_name,
            "kind": (
                "network_function"
                if service_name in NETWORK_FUNCTIONS
                else "supporting_service"
            ),
            "state": "running",
            "health": "healthy",
            "container_id": f"id-{service_name}",
            "published_ports": published_ports.get(service_name, []),
        })
    return {
        "id": "alpha",
        "name": "Network Alpha",
        "description": "Isolated Open5GS lab",
        "status": "running",
        "is_running": True,
        "configured_network_functions": len(NETWORK_FUNCTIONS),
        "service_count": len(EXPECTED_SERVICES),
        "running_services": len(EXPECTED_SERVICES),
        "healthy_services": len(EXPECTED_SERVICES),
        "services": services,
        "network_internal": True,
    }


def healthy_beta_environment(published_ports=None):
    environment = healthy_environment(published_ports)
    environment.update({
        "id": "beta",
        "name": "Network Beta",
        "description": "Isolated NRF runtime assessment lab",
        "configured_network_functions": 1,
        "service_count": 1,
        "running_services": 1,
        "healthy_services": 1,
        "services": [
            service
            for service in environment["services"]
            if service["name"] == "nrf"
        ],
    })
    return environment


class RuntimeEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "runtime-test.db"
        self.db_file_patch = patch.object(database, "DB_FILE", str(self.database_path))
        self.db_file_patch.start()
        self.addCleanup(self.db_file_patch.stop)
        self.addCleanup(self.temp_dir.cleanup)
        database.init_db()

    def test_manager_reports_health_and_only_published_host_ports(self):
        compose_path = Path(self.temp_dir.name) / "compose.yaml"
        compose_path.write_text("services: {}\n", encoding="utf-8")
        manager = Open5GSAlphaManager(compose_file=compose_path)
        rows = []
        for service_name in EXPECTED_SERVICES:
            row = {
                "Service": service_name,
                "State": "running",
                "Health": "healthy",
                "ID": f"id-{service_name}",
                "Publishers": [],
            }
            if service_name == "nrf":
                row["Publishers"] = [{
                    "URL": "127.0.0.1",
                    "PublishedPort": 7777,
                    "TargetPort": 7777,
                    "Protocol": "tcp",
                }]
            rows.append(json.dumps(row))
        with patch.object(
            manager,
            "_run",
            side_effect=[
                subprocess.CompletedProcess([], 0, "\n".join(rows), ""),
                subprocess.CompletedProcess([], 0, "true\n", ""),
            ],
        ):
            result = manager.get_status()

        self.assertEqual(result["status"], "running")
        self.assertEqual(result["configured_network_functions"], 8)
        self.assertEqual(result["healthy_services"], 9)
        nrf = next(item for item in result["services"] if item["name"] == "nrf")
        mongo = next(item for item in result["services"] if item["name"] == "mongodb")
        self.assertEqual(len(nrf["published_ports"]), 1)
        self.assertEqual(mongo["published_ports"], [])
        self.assertTrue(result["network_internal"])

    def test_manager_reads_docker_desktop_port_binding_label(self):
        published_ports = Open5GSAlphaManager._published_ports({
            "Publishers": [{
                "URL": "",
                "PublishedPort": 0,
                "TargetPort": 7777,
                "Protocol": "tcp",
            }],
            "Labels": (
                "com.docker.compose.service=nrf,"
                "desktop.docker.io/ports/7777/tcp=127.0.0.1:17777"
            ),
        })

        self.assertEqual(published_ports, [{
            "host": "127.0.0.1",
            "host_port": 17777,
            "target_port": 7777,
            "protocol": "tcp",
        }])

    def test_alpha_start_reuses_the_local_image_without_forcing_a_build(self):
        manager = Open5GSAlphaManager(
            compose_file=Path(self.temp_dir.name) / "compose.yaml"
        )
        with patch.object(manager, "_run") as run, patch.object(
            manager,
            "get_status",
            return_value=healthy_environment(),
        ):
            manager.start()

        run.assert_called_once_with(
            ["up", "--detach", "--wait", "--wait-timeout", "180"],
            timeout=300,
        )

    def test_assessment_separates_security_findings_from_tls_observations(self):
        environment = healthy_environment({
            "nrf": [{
                "host": "127.0.0.1",
                "host_port": 7777,
                "target_port": 7777,
                "protocol": "tcp",
            }]
        })
        with patch(
            "app.scanner.runtime_assessment.alpha_environment.get_status",
            return_value=environment,
        ):
            result = assess_network_alpha()

        self.assertEqual(result["summary"]["total_findings"], 1)
        self.assertEqual(result["summary"]["total_observations"], 8)
        self.assertEqual(result["findings"][0]["rule_id"], "RUNTIME-EXPOSURE-001")
        self.assertTrue(all(
            item["record_type"] == "observation"
            for item in result["observations"]
        ))
        saved = database.get_runtime_assessment(result["assessment_id"])
        self.assertEqual(len(saved["findings"]), 1)
        self.assertEqual(len(saved["observations"]), 8)

    def test_beta_loopback_publication_is_a_medium_finding_and_is_network_scoped(self):
        environment = healthy_beta_environment({
            "nrf": [{
                "host": "127.0.0.1",
                "host_port": 17777,
                "target_port": 7777,
                "protocol": "tcp",
            }]
        })
        with patch(
            "app.scanner.runtime_assessment.beta_environment.get_status",
            return_value=environment,
        ):
            result = assess_network_beta()

        self.assertEqual(result["network_id"], "beta")
        self.assertEqual(result["summary"]["total_findings"], 1)
        finding = result["findings"][0]
        self.assertEqual(finding["rule_id"], "RUNTIME-EXPOSURE-001")
        self.assertEqual(finding["severity"], "MEDIUM")
        self.assertIn("on loopback", finding["title"])
        self.assertEqual(
            database.get_latest_runtime_assessment("beta")["assessment_id"],
            result["assessment_id"],
        )
        self.assertEqual(database.list_runtime_assessments(10, "alpha"), [])
        self.assertEqual(len(database.list_runtime_assessments(10, "beta")), 1)

    def test_non_loopback_publication_is_a_high_finding(self):
        environment = healthy_environment({
            "nrf": [{
                "host": "0.0.0.0",
                "host_port": 7777,
                "target_port": 7777,
                "protocol": "tcp",
            }]
        })
        with patch(
            "app.scanner.runtime_assessment.alpha_environment.get_status",
            return_value=environment,
        ):
            result = assess_network_alpha()

        self.assertEqual(result["findings"][0]["severity"], "HIGH")

    def test_supporting_service_health_is_assessed(self):
        environment = healthy_environment()
        mongodb = next(
            service
            for service in environment["services"]
            if service["name"] == "mongodb"
        )
        mongodb["health"] = "unhealthy"
        with patch(
            "app.scanner.runtime_assessment.alpha_environment.get_status",
            return_value=environment,
        ):
            result = assess_network_alpha()

        self.assertEqual(result["summary"]["total_findings"], 1)
        self.assertEqual(result["findings"][0]["component"], "mongodb")
        self.assertEqual(result["findings"][0]["rule_id"], "RUNTIME-HEALTH-001")

    def test_stopped_services_are_runtime_findings_not_config_findings(self):
        environment = healthy_environment()
        environment["status"] = "stopped"
        environment["is_running"] = False
        environment["running_services"] = 0
        environment["healthy_services"] = 0
        for service in environment["services"]:
            service["state"] = "exited"
            service["health"] = "unknown"
        with patch(
            "app.scanner.runtime_assessment.alpha_environment.get_status",
            return_value=environment,
        ):
            result = assess_network_alpha()

        self.assertEqual(result["summary"]["total_findings"], len(EXPECTED_SERVICES))
        self.assertEqual(len(result["observations"]), 2)
        history = database.search_scan_history()
        self.assertEqual(history["total"], 1)
        self.assertEqual(history["scans"][0]["assessment_type"], "runtime")
        self.assertEqual(history["scans"][0]["file_type"], "runtime")
        stats = database.get_runtime_assessment_statistics()
        self.assertEqual(stats["total_runtime_findings"], len(EXPECTED_SERVICES))

    def test_environment_routes_call_controlled_manager_operations(self):
        with patch(
            "app.routes.environments.alpha_environment.get_status",
            return_value=healthy_environment(),
        ):
            response = asyncio.run(get_network_alpha())
        self.assertEqual(response["environment"]["status"], "running")

        with patch(
            "app.routes.environments.alpha_environment.start",
            return_value=healthy_environment(),
        ) as start:
            response = asyncio.run(start_network_alpha())
        start.assert_called_once_with()
        self.assertEqual(response["status"], "success")

        stopped = healthy_environment()
        stopped.update({"status": "stopped", "is_running": False})
        with patch(
            "app.routes.environments.alpha_environment.stop",
            return_value=stopped,
        ) as stop:
            response = asyncio.run(stop_network_alpha())
        stop.assert_called_once_with()
        self.assertEqual(response["environment"]["status"], "stopped")

        with patch(
            "app.scanner.runtime_assessment.alpha_environment.get_status",
            return_value=healthy_environment(),
        ):
            response = asyncio.run(assess_network_alpha_route())
        self.assertEqual(response["assessment_type"], "runtime")
        self.assertEqual(response["status"], "success")

    def test_beta_manager_and_routes_use_beta_compose_project(self):
        compose_path = Path(self.temp_dir.name) / "beta-compose.yaml"
        compose_path.write_text("services: {}\n", encoding="utf-8")
        manager = Open5GSBetaManager(compose_file=compose_path)
        self.assertEqual(manager.project_name, "susignal-network-beta")
        self.assertEqual(manager.environment_id, "beta")
        self.assertEqual(manager.network_functions, ("nrf",))
        self.assertEqual(manager.expected_services, ("nrf",))
        self.assertFalse(manager.build_on_start)

        with patch(
            "app.routes.environments.beta_environment.get_status",
            return_value=healthy_beta_environment(),
        ):
            response = asyncio.run(get_network_beta())
        self.assertEqual(response["environment"]["id"], "beta")

        with patch(
            "app.routes.environments.beta_environment.start",
            return_value=healthy_beta_environment(),
        ) as start:
            response = asyncio.run(start_network_beta())
        start.assert_called_once_with()
        self.assertEqual(response["environment"]["id"], "beta")

        stopped = healthy_beta_environment()
        stopped.update({"status": "stopped", "is_running": False})
        with patch(
            "app.routes.environments.beta_environment.stop",
            return_value=stopped,
        ) as stop:
            response = asyncio.run(stop_network_beta())
        stop.assert_called_once_with()
        self.assertEqual(response["environment"]["status"], "stopped")

        with patch(
            "app.scanner.runtime_assessment.beta_environment.get_status",
            return_value=healthy_beta_environment({
                "nrf": [{
                    "host": "127.0.0.1",
                    "host_port": 17777,
                    "target_port": 7777,
                    "protocol": "tcp",
                }]
            }),
        ):
            response = asyncio.run(assess_network_beta_route())
        self.assertEqual(response["network_id"], "beta")
        self.assertEqual(response["findings"][0]["severity"], "MEDIUM")

    def test_existing_runtime_history_is_migrated_to_alpha_network_id(self):
        legacy_path = Path(self.temp_dir.name) / "legacy-runtime.db"
        connection = sqlite3.connect(legacy_path)
        try:
            connection.execute("""
                CREATE TABLE runtime_assessments (
                    assessment_id TEXT PRIMARY KEY,
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
            connection.execute("""
                INSERT INTO runtime_assessments (
                    assessment_id, network_name, assessed_at, assessment_status,
                    summary_json, environment_status_json
                ) VALUES ('legacy-id', 'Network Alpha', '2025-01-01T00:00:00Z',
                          'COMPLETED', '{}', '{}')
            """)
            connection.commit()
        finally:
            connection.close()

        with patch.object(database, "DB_FILE", str(legacy_path)):
            database.init_db()
            connection = sqlite3.connect(legacy_path)
            try:
                row = connection.execute(
                    "SELECT network_id FROM runtime_assessments "
                    "WHERE assessment_id = 'legacy-id'"
                ).fetchone()
            finally:
                connection.close()
        self.assertEqual(row[0], "alpha")

    def test_new_runtime_tables_do_not_replace_configuration_tables(self):
        conn = sqlite3.connect(self.database_path)
        try:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        finally:
            conn.close()
        self.assertIn("scans", tables)
        self.assertIn("findings", tables)
        self.assertIn("runtime_assessments", tables)
        self.assertIn("runtime_assessment_records", tables)


if __name__ == "__main__":
    unittest.main()
