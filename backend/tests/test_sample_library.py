import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.scanner.analyzer import analyze_configuration
from app.scanner.parser import detect_network_function_type, parse_configuration


ROOT_DIR = Path(__file__).resolve().parents[2]
SAMPLE_ROOT = ROOT_DIR / "frontend" / "public" / "sample_configs"


class SampleLibraryTests(unittest.TestCase):
    def test_manifest_samples_parse_and_match_expected_findings(self):
        manifest = json.loads(
            (SAMPLE_ROOT / "manifest.json").read_text(encoding="utf-8")
        )
        samples = manifest["samples"]
        self.assertGreaterEqual(len(samples), 15)
        self.assertEqual(len({sample["id"] for sample in samples}), len(samples))

        for sample in samples:
            with self.subTest(sample=sample["id"]):
                sample_path = SAMPLE_ROOT / sample["path"]
                raw_content = sample_path.read_text(encoding="utf-8")
                config = parse_configuration(raw_content, sample_path.name)
                self.assertEqual(
                    detect_network_function_type(config, sample_path.name),
                    sample["network_function"],
                )

                result = analyze_configuration(config, sample_path.name)
                rule_ids = sorted(
                    finding["rule_id"] for finding in result["findings"]
                )
                self.assertEqual(rule_ids, sorted(sample["expected_rule_ids"]))
                self.assertEqual(
                    sample["contains_known_test_vulnerabilities"],
                    bool(rule_ids),
                )


if __name__ == "__main__":
    unittest.main()
