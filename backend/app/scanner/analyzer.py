from typing import Dict, Any, List
from .rules import get_all_rules, SecurityRule
from .risk import SeverityLevel, get_severity_weight
from .parser import detect_network_function_type
from .open5gs_rules import get_open5gs_rules


def _is_open5gs_configuration(config_data: Dict[str, Any]) -> bool:
    """Recognize Open5GS NF-specific server configuration without optional sections."""
    if not isinstance(config_data, dict):
        return False

    for nf_name in ("amf", "ausf", "nrf", "pcf", "smf", "udm", "upf"):
        nf_config = config_data.get(nf_name)
        if not isinstance(nf_config, dict):
            continue

        server_sections = ("pfcp", "gtpu") if nf_name == "upf" else ("sbi",)
        for section_name in server_sections:
            section = nf_config.get(section_name)
            if not isinstance(section, dict):
                continue

            servers = section.get("server")
            if isinstance(servers, list) and any(
                isinstance(server, dict)
                and ("address" in server or "dev" in server)
                for server in servers
            ):
                return True

    return False


def analyze_configuration(
    config_data: Dict[str, Any],
    filename: str = ""
) -> Dict[str, Any]:
    """
    Central coordinator of the security analysis process.
    Receives parsed configuration data, evaluates security rules,
    classifies risks, and aggregates findings.
    """
    detected_nf = detect_network_function_type(config_data, filename)
    rules: List[SecurityRule] = get_all_rules()

    if _is_open5gs_configuration(config_data):
        rules = [
            rule for rule in rules
            if rule.rule_id != "5GS-CRYP-001"
        ]
        rules.extend(get_open5gs_rules())

    findings: List[Dict[str, Any]] = []
    rules_checked = 0

    for rule in rules:
        # Check rule if it targets this NF or applies globally (ALL)
        if rule.target_nf in ["ALL", detected_nf]:
            rules_checked += 1
            finding = rule.check(config_data)
            if finding:
                findings.append(finding)

    # Calculate severity counts
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }

    total_risk_penalty = 0
    for finding in findings:
        sev = finding.get("severity", "").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
        total_risk_penalty += get_severity_weight(finding.get("severity", ""))

    # Compute a 0-100 baseline Security Health Score (100 is pristine, penalised by findings)
    computed_score = max(0, 100 - (total_risk_penalty * 2))

    summary = {
        "network_function": detected_nf,
        "total_rules_checked": rules_checked,
        "total_findings": len(findings),
        "critical": severity_counts["critical"],
        "high": severity_counts["high"],
        "medium": severity_counts["medium"],
        "low": severity_counts["low"],
        "security_score": computed_score,
        "status": "VULNERABILITIES_FOUND" if findings else "CLEAN"
    }

    return {
        "summary": summary,
        "findings": findings
    }
