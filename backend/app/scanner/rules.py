"""
Modular Security Rules Engine for 5G Core Network Functions.

Each rule defines:
- rule_id: Unique rule identifier (e.g., 5GS-AMF-001)
- title: Short description of the misconfiguration
- target_nf: Applicable Network Function (AMF, SMF, UPF, NRF, AUSF, UDM, or ALL)
- severity: SeverityLevel (CRITICAL, HIGH, MEDIUM, LOW)
- category: Security domain (Encryption, Transport, Access Control, Hardening)
- description: Detailed risk explanation
- remediation: Prescriptive fix recommendation
- evaluate(config: dict) -> bool (True if misconfiguration detected)
"""

from typing import List, Dict, Any, Callable, Optional
from .risk import SeverityLevel


class SecurityRule:
    def __init__(
        self,
        rule_id: str,
        title: str,
        target_nf: str,
        severity: SeverityLevel,
        category: str,
        description: str,
        remediation: str,
        evaluator: Callable[[Dict[str, Any]], bool]
    ):
        self.rule_id = rule_id
        self.title = title
        self.target_nf = target_nf
        self.severity = severity
        self.category = category
        self.description = description
        self.remediation = remediation
        self.evaluator = evaluator

    def check(self, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Executes rule against parsed config.
        Returns a finding dictionary if a misconfiguration is detected, else None.
        """
        try:
            is_violation = self.evaluator(config)
            if is_violation:
                return {
                    "rule_id": self.rule_id,
                    "title": self.title,
                    "target_nf": self.target_nf,
                    "severity": self.severity.value,
                    "category": self.category,
                    "description": self.description,
                    "remediation": self.remediation
                }
        except Exception:
            # Defensive execution: individual rule errors should not crash the entire scan
            return None
        return None


# Helper traversal functions for nested dicts
def _get_nested(d: Dict[str, Any], *keys, default=None):
    """
    Search for nested keys in dictionary.
    Also transparently searches within top-level NF blocks (e.g. d['amf']['sbi']).
    """
    def _find_in_dict(target: Dict[str, Any], path):
        cur = target
        for k in path:
            if isinstance(cur, dict) and k in cur:
                cur = cur[k]
            else:
                return default
        return cur

    # First attempt: search directly from root
    val = _find_in_dict(d, keys)
    if val is not default:
        return val

    # Second attempt: search within any top-level sub-dictionary (e.g. amf, smf, upf, configuration)
    for root_key, sub_dict in d.items():
        if isinstance(sub_dict, dict):
            val = _find_in_dict(sub_dict, keys)
            if val is not default:
                return val

    return default


def _rule_null_encryption(config: Dict[str, Any]) -> bool:
    """Flag if NEA0 / null encryption is permitted or set as preferred."""
    ciphers = _get_nested(config, "security", "ciphering_order", default=[])
    if isinstance(ciphers, list) and len(ciphers) > 0:
        # If NEA0 is first or included in ciphering order
        first_cipher = str(ciphers[0]).upper()
        if "NEA0" in first_cipher:
            return True
        # If NEA0 is in list and emergency is not segregated
        if any("NEA0" in str(c).upper() for c in ciphers):
            return True

    config_str = str(config).lower()
    if "nea0" in config_str or "null_encryption: true" in config_str:
        return True
    return False


def _rule_plaintext_sbi(config: Dict[str, Any]) -> bool:
    """Flag if Service Based Interface (SBI) uses unencrypted HTTP/1.1 instead of HTTPS."""
    scheme = _get_nested(config, "sbi", "scheme", default="")
    tls = _get_nested(config, "sbi", "tls", default=None)
    
    if str(scheme).lower() == "http":
        return True
    if isinstance(tls, dict) and tls.get("enabled") is False:
        return True
    if tls is False or tls == "disabled":
        return True
    
    # Generic check in root
    tls_root = _get_nested(config, "tls", "enabled", default=None)
    if tls_root is False:
        return True
        
    return False


def _rule_wildcard_bind(config: Dict[str, Any]) -> bool:
    """Flag if binding directly to wildcard 0.0.0.0 without firewall/ACL limits."""
    sbi_addr = _get_nested(config, "sbi", "addr", default="")
    server_addr = _get_nested(config, "sbi", "server", "addr", default="")
    bind_addr = _get_nested(config, "bind_addr", default="")
    ngap_addr = _get_nested(config, "ngap", "addr", default="")
    
    if any(addr == "0.0.0.0" for addr in [sbi_addr, server_addr, bind_addr, ngap_addr]):
        return True
    return False


def _rule_missing_mtls_nrf(config: Dict[str, Any]) -> bool:
    """Flag if NRF mutual TLS client validation is explicitly disabled."""
    mtls = _get_nested(config, "nrf", "client_auth", default=None)
    if mtls is False or str(mtls).lower() in ["disabled", "none", "optional"]:
        return True
    return False


# Default registry for starter rules
RULE_REGISTRY: List[SecurityRule] = [
    SecurityRule(
        rule_id="5GS-CRYP-001",
        title="Null Ciphering Enabled (NEA0)",
        target_nf="AMF",
        severity=SeverityLevel.CRITICAL,
        category="Cryptographic Protection",
        description="The AMF allows or prioritizes NEA0 (null ciphering), allowing non-emergency NAS traffic to be transmitted in plaintext without confidentiality protection.",
        remediation="Remove NEA0 from ciphering_order in the security block. Enforce NEA1 (128-EEA1/SNOW 3G), NEA2 (128-EEA2/AES), or NEA3 (128-EEA3/ZUC).",
        evaluator=_rule_null_encryption
    ),
    SecurityRule(
        rule_id="5GS-SBI-002",
        title="Insecure HTTP Scheme on Service Based Interface",
        target_nf="ALL",
        severity=SeverityLevel.HIGH,
        category="Transport Security",
        description="Network Function SBI endpoints are configured with unencrypted 'http' scheme instead of 'https', exposing inter-NF API traffic to sniffing and MITM attacks (3GPP TS 33.501 Section 13.1).",
        remediation="Change sbi.scheme to 'https' and supply valid TLS server certificates, private keys, and trusted CA bundles.",
        evaluator=_rule_plaintext_sbi
    ),
    SecurityRule(
        rule_id="5GS-NET-003",
        title="Wildcard Service Address Binding (0.0.0.0)",
        target_nf="ALL",
        severity=SeverityLevel.MEDIUM,
        category="Network Hardening",
        description="The Network Function binds service listening interfaces to wildcard 0.0.0.0, potentially exposing control plane interfaces across unintended networks or management planes.",
        remediation="Bind service endpoints to specific dedicated internal network slice interfaces or isolated loopback addresses.",
        evaluator=_rule_wildcard_bind
    ),
    SecurityRule(
        rule_id="5GS-AUTH-004",
        title="Disabled Mutual TLS (mTLS) for NF Authentication",
        target_nf="NRF",
        severity=SeverityLevel.HIGH,
        category="Authentication & Access Control",
        description="Client certificate authentication is disabled on the NRF. Rogues or compromised Network Functions can register themselves without cryptographic proof of identity.",
        remediation="Set nrf.client_auth to 'required' and configure mutual TLS (mTLS) trust anchor verification.",
        evaluator=_rule_missing_mtls_nrf
    )
]


def get_all_rules() -> List[SecurityRule]:
    """Retrieve all registered security rules."""
    return RULE_REGISTRY
