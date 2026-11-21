import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.scanner.open5gs_rules import get_open5gs_rules
from app.scanner.analyzer import (
    _is_open5gs_configuration,
    analyze_configuration,
)
from app.scanner.parser import detect_network_function_type, parse_configuration
from app.scanner.rules import SecurityRule, get_all_rules
from app.scanner.risk import SeverityLevel


ROOT_DIR = Path(__file__).resolve().parents[2]
BACKEND_DIR = Path(__file__).resolve().parents[1]
OPEN5GS_DIR = ROOT_DIR / "sample_configs" / "open5gs"
RULES_BY_ID = {rule.rule_id: rule for rule in get_open5gs_rules()}


class Open5GSRuleTests(unittest.TestCase):
    def test_security_score_for_two_high_and_one_medium_finding(self):
        config = {
            "amf": {
                "sbi": {
                    "server": [{"address": "127.0.0.5"}],
                    "client": {
                        "scp": [{"uri": "http://127.0.0.200:7777"}]
                    },
                },
                "security": {
                    "integrity_order": ["NIA0"],
                    "ciphering_order": ["NEA0"],
                },
            }
        }

        result = analyze_configuration(config, "amf.yaml")
        summary = result["summary"]

        self.assertEqual(summary["high"], 2)
        self.assertEqual(summary["medium"], 1)
        self.assertEqual(summary["security_score"], 64)

    def test_actual_open5gs_files(self):
        expected_sbi_findings = {
            "amf.yaml",
            "ausf.yaml",
            "pcf.yaml",
            "smf.yaml",
            "udm.yaml",
        }

        for filename in (
            "amf.yaml",
            "ausf.yaml",
            "nrf.yaml",
            "pcf.yaml",
            "smf.yaml",
            "udm.yaml",
            "upf.yaml",
        ):
            with self.subTest(filename=filename):
                config = parse_configuration(
                    (OPEN5GS_DIR / filename).read_text(encoding="utf-8"),
                    filename,
                )
                self.assertEqual(
                    RULES_BY_ID["OPEN5GS-SBI-001"].check(config) is not None,
                    filename in expected_sbi_findings,
                )

                is_amf = filename == "amf.yaml"
                self.assertEqual(
                    RULES_BY_ID["OPEN5GS-AMF-001"].check(config) is not None,
                    is_amf,
                )
                self.assertEqual(
                    RULES_BY_ID["OPEN5GS-AMF-002"].check(config) is not None,
                    is_amf,
                )

    def test_nf_detection_without_filename_and_with_filename(self):
        expected_nfs = {
            "amf.yaml": "AMF",
            "ausf.yaml": "AUSF",
            "nrf.yaml": "NRF",
            "pcf.yaml": "PCF",
            "smf.yaml": "SMF",
            "udm.yaml": "UDM",
            "upf.yaml": "UPF",
        }

        for filename, expected_nf in expected_nfs.items():
            with self.subTest(filename=filename):
                config = parse_configuration(
                    (OPEN5GS_DIR / filename).read_text(encoding="utf-8"),
                    filename,
                )
                self.assertEqual(
                    detect_network_function_type(config),
                    expected_nf,
                )
                self.assertEqual(
                    detect_network_function_type(config, filename),
                    expected_nf,
                )

    def test_null_algorithm_rules_handle_malformed_security(self):
        malformed_configs = [
            {"amf": None},
            {"amf": {"security": None}},
            {"amf": {"security": "invalid"}},
            {"amf": {}},
            {"amf": {"security": {}}},
            {},
        ]

        for config in malformed_configs:
            with self.subTest(config=config):
                self.assertFalse(RULES_BY_ID["OPEN5GS-AMF-001"].evaluator(config))
                self.assertFalse(RULES_BY_ID["OPEN5GS-AMF-002"].evaluator(config))

    def test_missing_and_malformed_client_configurations(self):
        configurations = [
            {"amf": {"sbi": {}}},
            {"amf": {"sbi": {"client": {}}}},
            {"amf": {"sbi": {"client": ["http://nrf.local"]}}},
            {"amf": {"sbi": {"client": {"nrf": [{"uri": None}]}}}},
            {"amf": {"sbi": {"client": {"nrf": [{"uri": "http://"}]}}}},
        ]

        for config in configurations:
            with self.subTest(config=config):
                self.assertIsNone(
                    RULES_BY_ID["OPEN5GS-SBI-001"].check(config)
                )

    def test_https_is_not_flagged(self):
        config = {
            "amf": {
                "sbi": {
                    "client": {
                        "nrf": [{"uri": "https://nrf.example:7777"}]
                    }
                }
            }
        }

        self.assertIsNone(RULES_BY_ID["OPEN5GS-SBI-001"].check(config))

    def test_multiple_client_groups_and_uppercase_http(self):
        config = {
            "amf": {
                "sbi": {
                    "client": {
                        "nrf": [{"uri": "https://nrf.example:7777"}],
                        "scp": [{"uri": "HTTP://scp.example:7777"}],
                        "custom": {
                            "service": [{"uri": "http://service.example:7777"}]
                        },
                    }
                }
            }
        }

        self.assertIsNotNone(RULES_BY_ID["OPEN5GS-SBI-001"].check(config))

    def test_explicit_http_uri_remains_http_with_default_https_scheme(self):
        config = {
            "default": {"tls": {"client": {"scheme": "https"}}},
            "amf": {
                "sbi": {
                    "client": {
                        "scp": [{"uri": "http://scp.example:7777"}]
                    }
                }
            },
        }

        self.assertIsNotNone(RULES_BY_ID["OPEN5GS-SBI-001"].check(config))

    def test_commented_yaml_uri_is_ignored(self):
        config = parse_configuration(
            """
amf:
  sbi:
    client: {}
#    scp:
#      - uri: http://scp.example:7777
""",
            "amf.yaml",
        )

        self.assertIsNone(RULES_BY_ID["OPEN5GS-SBI-001"].check(config))

    def test_analyzer_integration_for_open5gs_and_pcf(self):
        expected_findings = {
            "amf.yaml": {
                "OPEN5GS-AMF-001",
                "OPEN5GS-AMF-002",
                "OPEN5GS-SBI-001",
            },
            "ausf.yaml": {"OPEN5GS-SBI-001"},
            "nrf.yaml": set(),
            "pcf.yaml": {"OPEN5GS-SBI-001"},
            "smf.yaml": {"OPEN5GS-SBI-001"},
            "udm.yaml": {"OPEN5GS-SBI-001"},
            "upf.yaml": set(),
        }

        for filename, expected_rule_ids in expected_findings.items():
            with self.subTest(filename=filename):
                config = parse_configuration(
                    (OPEN5GS_DIR / filename).read_text(encoding="utf-8"),
                    filename,
                )
                result = analyze_configuration(config, filename)
                rule_ids = {finding["rule_id"] for finding in result["findings"]}
                open5gs_rule_ids = {
                    rule_id
                    for rule_id in rule_ids
                    if rule_id.startswith("OPEN5GS-")
                }

                self.assertEqual(open5gs_rule_ids, expected_rule_ids)
                self.assertNotIn("5GS-CRYP-001", rule_ids)
                if filename == "nrf.yaml":
                    self.assertNotIn("5GS-AUTH-004", rule_ids)
                for rule_id in expected_rule_ids:
                    self.assertEqual(
                        sum(
                            finding["rule_id"] == rule_id
                            for finding in result["findings"]
                        ),
                        1,
                    )

        pcf_config = parse_configuration(
            (OPEN5GS_DIR / "pcf.yaml").read_text(encoding="utf-8"),
            "pcf.yaml",
        )
        self.assertEqual(detect_network_function_type(pcf_config), "PCF")

    def test_open5gs_detection_allows_missing_optional_sections(self):
        for filename in ("amf.yaml", "upf.yaml"):
            for omitted_sections in (
                ("global",),
                ("logger",),
                ("global", "logger"),
            ):
                with self.subTest(filename=filename, omitted=omitted_sections):
                    config = parse_configuration(
                        (OPEN5GS_DIR / filename).read_text(encoding="utf-8"),
                        filename,
                    )
                    for section in omitted_sections:
                        config.pop(section)

                    self.assertTrue(_is_open5gs_configuration(config))

                    if filename == "amf.yaml":
                        findings = analyze_configuration(
                            config,
                            filename,
                        )["findings"]
                        rule_ids = {finding["rule_id"] for finding in findings}
                        self.assertIn("OPEN5GS-SBI-001", rule_ids)
                        self.assertIn("OPEN5GS-AMF-001", rule_ids)
                        self.assertIn("OPEN5GS-AMF-002", rule_ids)

        for directory_name in ("baseline", "seeded_vulnerable"):
            directory = ROOT_DIR / "sample_configs" / directory_name
            for config_path in directory.glob("*.yaml"):
                with self.subTest(config=config_path):
                    config = parse_configuration(
                        config_path.read_text(encoding="utf-8"),
                        config_path.name,
                    )
                    self.assertFalse(_is_open5gs_configuration(config))

    def test_existing_simplified_configurations_keep_generic_rules(self):
        config_paths = []
        for directory_name in ("baseline", "seeded_vulnerable"):
            directory = ROOT_DIR / "sample_configs" / directory_name
            config_paths.extend(
                (path, path.name == "amf.yaml")
                for path in sorted(directory.glob("*.yaml"))
            )
        config_paths.extend(
            [
                (BACKEND_DIR / "sample_configs" / "amf_vulnerable.yaml", True),
                (BACKEND_DIR / "sample_configs" / "amf_hardened.yaml", False),
            ]
        )

        for config_path, should_have_null_ciphering in config_paths:
            with self.subTest(config=config_path.name, parent=config_path.parent.name):
                config = parse_configuration(
                    config_path.read_text(encoding="utf-8"),
                    config_path.name,
                )
                findings = analyze_configuration(config, config_path.name)["findings"]
                rule_ids = {finding["rule_id"] for finding in findings}

                self.assertFalse(any(rule_id.startswith("OPEN5GS-") for rule_id in rule_ids))
                self.assertEqual(
                    "5GS-CRYP-001" in rule_ids,
                    should_have_null_ciphering,
                )

    def test_missing_nrf_mtls_field_is_not_reported_as_disabled(self):
        mtls_rule = next(
            rule
            for rule in get_all_rules()
            if rule.rule_id == "5GS-AUTH-004"
        )
        open5gs_nrf = parse_configuration(
            (OPEN5GS_DIR / "nrf.yaml").read_text(encoding="utf-8"),
            "nrf.yaml",
        )

        self.assertIsNone(mtls_rule.check(open5gs_nrf))
        self.assertIsNone(mtls_rule.check({"nrf": {}}))
        self.assertIsNone(mtls_rule.check({"nrf": {"client_auth": None}}))

        for disabled_value in (False, "false", "disabled", "none", "optional"):
            with self.subTest(disabled_value=disabled_value):
                finding = mtls_rule.check(
                    {"nrf": {"client_auth": disabled_value}}
                )
                self.assertIsNotNone(finding)

    def test_rule_evaluation_errors_are_logged_without_changing_result_shape(self):
        failing_rule = SecurityRule(
            rule_id="TEST-ERROR-001",
            title="Test error",
            target_nf="ALL",
            severity=SeverityLevel.LOW,
            category="Test",
            description="Test evaluator failure",
            remediation="No action",
            evaluator=lambda config: (_ for _ in ()).throw(
                ValueError("sensitive config value")
            ),
        )

        with self.assertLogs("app.scanner.rules", level="ERROR") as logs:
            self.assertIsNone(failing_rule.check({}))

        self.assertIn("TEST-ERROR-001", logs.output[0])
        self.assertIn("ValueError", logs.output[0])
        self.assertNotIn("sensitive config value", logs.output[0])


if __name__ == "__main__":
    unittest.main()
