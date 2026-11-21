from urllib.parse import urlsplit
from typing import Dict, Any, List
from .risk import SeverityLevel
from .rules import SecurityRule


def check_unencrypted_sbi_client(config: Dict[str, Any]) -> bool:
    """Detect explicit HTTP client URIs in Open5GS SBI configuration."""

    def contains_http_uri(value: Any) -> bool:
        if isinstance(value, dict):
            uri = value.get("uri")
            if isinstance(uri, str):
                try:
                    parsed_uri = urlsplit(uri.strip())
                except ValueError:
                    parsed_uri = None
                if (
                    parsed_uri is not None
                    and parsed_uri.scheme.lower() == "http"
                    and parsed_uri.netloc
                ):
                    return True
            return any(contains_http_uri(child) for child in value.values())

        if isinstance(value, list):
            return any(contains_http_uri(child) for child in value)

        return False

    if not isinstance(config, dict):
        return False

    for nf_name in ("amf", "ausf", "nrf", "pcf", "smf", "udm", "upf"):
        nf_config = config.get(nf_name)
        if not isinstance(nf_config, dict):
            continue

        sbi = nf_config.get("sbi")
        if not isinstance(sbi, dict):
            continue

        client = sbi.get("client")
        if isinstance(client, dict) and contains_http_uri(client):
            return True

    return False


def check_null_integrity(config: Dict[str, Any]) -> bool:
    """Detect NIA0 (null integrity protection) in AMF."""

    if not isinstance(config, dict):
        return False

    amf = config.get("amf")
    if not isinstance(amf, dict):
        return False

    security = amf.get("security")
    if not isinstance(security, dict):
        return False

    algorithms = security.get("integrity_order")

    return (
        isinstance(algorithms, list)
        and any(str(algo).upper() == "NIA0" for algo in algorithms)
    )


def check_null_ciphering(config: Dict[str, Any]) -> bool:
    """Detect NEA0 (null ciphering) in AMF."""

    if not isinstance(config, dict):
        return False

    amf = config.get("amf")
    if not isinstance(amf, dict):
        return False

    security = amf.get("security")
    if not isinstance(security, dict):
        return False

    algorithms = security.get("ciphering_order")

    return (
        isinstance(algorithms, list)
        and any(str(algo).upper() == "NEA0" for algo in algorithms)
    )


OPEN5GS_RULES: List[SecurityRule] = [

    SecurityRule(
        rule_id="OPEN5GS-AMF-001",
        title="Null Integrity Algorithm Enabled (NIA0)",
        target_nf="AMF",
        severity=SeverityLevel.HIGH,
        category="Cryptographic Protection",
        description="The AMF configuration includes NIA0, which provides no NAS integrity protection.",
        remediation="Remove NIA0 from the AMF integrity_order configuration and use supported integrity-protected algorithms.",
        evaluator=check_null_integrity
    ),

    SecurityRule(
        rule_id="OPEN5GS-AMF-002",
        title="Null Ciphering Algorithm Enabled (NEA0)",
        target_nf="AMF",
        severity=SeverityLevel.HIGH,
        category="Cryptographic Protection",
        description="The AMF configuration includes NEA0, which provides no NAS confidentiality protection.",
        remediation="Remove NEA0 from the AMF ciphering_order configuration where null ciphering is not explicitly required.",
        evaluator=check_null_ciphering
    ),

    SecurityRule(
        rule_id="OPEN5GS-SBI-001",
        title="Unencrypted SBI Client Connection",
        target_nf="ALL",
        severity=SeverityLevel.MEDIUM,
        category="Transport Security",
        description="An Open5GS SBI client URI explicitly selects HTTP. Open5GS uses this URI scheme for the client transport, so this connection does not use TLS.",
        remediation="Change each HTTP SBI client URI to HTTPS and configure the required trusted CA certificate and, where mutual TLS is required, the client certificate and private key. Configure the peer SBI server with its TLS certificate and key.",
        evaluator=check_unencrypted_sbi_client
    )
]


def get_open5gs_rules() -> List[SecurityRule]:
    return OPEN5GS_RULES