from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any, Dict, List
import uuid

from ..database.db import save_runtime_assessment
from ..integrations.open5gs_alpha import (
    Open5GSAlphaManager,
    alpha_environment,
    beta_environment,
)


def _is_loopback_host(host: Any) -> bool:
    normalized_host = str(host or "").strip().lower()
    if normalized_host == "localhost":
        return True
    try:
        return ip_address(normalized_host.strip("[]")).is_loopback
    except ValueError:
        return False


def assess_environment(environment_manager: Open5GSAlphaManager) -> Dict[str, Any]:
    environment = environment_manager.get_status()
    network_name = environment["name"]
    findings: List[Dict[str, Any]] = []
    observations: List[Dict[str, Any]] = []

    for service in environment["services"]:
        name = service["name"]
        is_network_function = service["kind"] == "network_function"
        component_label = (
            f"Network Function {name.upper()}"
            if is_network_function
            else f"Supporting service {name}"
        )
        if service["state"] != "running":
            findings.append({
                "record_type": "finding",
                "rule_id": "RUNTIME-AVAIL-001",
                "severity": "HIGH",
                "title": f"Expected {component_label} is unavailable",
                "component": name,
                "description": (
                    f"The configured {network_name} {component_label.lower()} is not "
                    "running."
                ),
                "evidence": (
                    f"Compose reports state '{service['state']}' and health "
                    f"'{service['health']}'."
                ),
                "remediation": (
                    f"Start {network_name} and inspect this service's Docker Compose "
                    "logs if it does not become healthy."
                ),
            })
        elif service["health"] in {"unhealthy", "starting"}:
            findings.append({
                "record_type": "finding",
                "rule_id": "RUNTIME-HEALTH-001",
                "severity": "MEDIUM",
                "title": f"{component_label} healthcheck has not passed",
                "component": name,
                "description": (
                    f"The {component_label.lower()} process is running but its configured "
                    "healthcheck has not passed."
                ),
                "evidence": f"Compose reports health '{service['health']}'.",
                "remediation": (
                    "Review the service logs and dependencies, then restore the "
                    "service and its configured healthcheck."
                ),
            })
        elif (
            service["health"] == "healthy"
            and is_network_function
            and name != "upf"
        ):
            observations.append({
                "record_type": "observation",
                "rule_id": "RUNTIME-TLS-OBSERVED",
                "severity": "INFO",
                "title": f"{name.upper()} SBI TLS listener is reachable",
                "component": name,
                "description": (
                    "The configured healthcheck established an HTTPS/TLS connection "
                    "to the SBI listener from the private Docker network."
                ),
                "evidence": (
                    f"Compose reports the {name} service healthy. Its healthcheck "
                    "validates the peer hostname and CA and presents a client "
                    "certificate to port 7777."
                ),
            })
        elif service["health"] not in {"healthy", "unhealthy", "starting"}:
            observations.append({
                "record_type": "observation",
                "rule_id": "RUNTIME-HEALTH-UNVERIFIED",
                "severity": "INFO",
                "title": f"{component_label} health is not reported",
                "component": name,
                "description": (
                    "Docker Compose did not report a healthcheck result for this "
                    "running service, so its application-level health is unverified."
                ),
                "evidence": f"Compose reports health '{service['health']}'.",
            })

    for service in environment["services"]:
        for port in service["published_ports"]:
            host = str(port.get("host") or "0.0.0.0")
            loopback_only = _is_loopback_host(host)
            findings.append({
                "record_type": "finding",
                "rule_id": "RUNTIME-EXPOSURE-001",
                "severity": "MEDIUM" if loopback_only else "HIGH",
                "title": (
                    f"{service['name']} publishes a host port on loopback"
                    if loopback_only
                    else f"{service['name']} publishes a host port"
                ),
                "component": service["name"],
                "description": (
                    (
                        f"The {service['name']} port is bound to the host loopback "
                        "interface. Processes on the host can reach it, but it is "
                        "not bound to other host network interfaces."
                    )
                    if loopback_only
                    else (
                        f"The {service['name']} port is published beyond the "
                        f"internal-only {network_name} Docker network."
                    )
                ),
                "evidence": (
                    f"{host}:{port['host_port']} maps to "
                    f"{port['target_port']}/{port['protocol']}."
                ),
                "remediation": (
                    "Remove the host port mapping unless host access is explicitly "
                    "required. If local host access is needed, keep the binding on "
                    "loopback and do not bind it to all interfaces."
                ),
            })

    if environment["network_internal"] is False:
        findings.append({
            "record_type": "finding",
            "rule_id": "RUNTIME-NETWORK-001",
            "severity": "HIGH",
            "title": f"{network_name} Docker network is not internal",
            "component": "core",
            "description": (
                "The Docker network is not configured as an internal-only network."
            ),
            "evidence": f"Docker reports the {network_name} core network Internal=false.",
            "remediation": (
                "Set the Compose core network to internal: true and recreate the "
                "network."
            ),
        })
    elif environment["network_internal"] is True:
        observations.append({
            "record_type": "observation",
            "rule_id": "RUNTIME-NETWORK-OBSERVED",
            "severity": "INFO",
            "title": f"{network_name} core network is internal",
            "component": "core",
            "description": (
                f"Docker reports the {network_name} core network as internal-only."
            ),
            "evidence": (
                f"Docker reports the {network_name} core network Internal=true."
            ),
        })
    else:
        observations.append({
            "record_type": "observation",
            "rule_id": "RUNTIME-NETWORK-UNVERIFIED",
            "severity": "INFO",
            "title": f"{network_name} isolation could not be verified",
            "component": "core",
            "description": (
                "The Docker network inspection did not return a definitive "
                "internal-only status."
            ),
            "evidence": "Docker did not report the core network Internal property.",
        })

    if not any(
        service["published_ports"]
        for service in environment["services"]
    ):
        observations.append({
            "record_type": "observation",
            "rule_id": "RUNTIME-EXPOSURE-OBSERVED",
            "severity": "INFO",
            "title": f"No {network_name} host ports are published",
            "component": "core",
            "description": (
                f"Docker Compose reports no {network_name} service ports published "
                "on the host."
            ),
            "evidence": (
                "No non-zero PublishedPort values were returned for the expected "
                "services."
            ),
        })

    counts = {
        severity.lower(): sum(
            item["severity"] == severity for item in findings
        )
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    }
    assessed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    assessment_id = str(uuid.uuid4())
    summary = {
        **counts,
        "total_findings": len(findings),
        "total_observations": len(observations),
        "services_healthy": environment["healthy_services"],
        "services_configured": environment["service_count"],
        "status": "FINDINGS_FOUND" if findings else "CLEAN",
    }
    result = {
        "assessment_id": assessment_id,
        "assessment_type": "runtime",
        "network_id": environment["id"],
        "network_name": network_name,
        "assessed_at": assessed_at,
        "assessment_status": "COMPLETED",
        "summary": summary,
        "environment_status": environment,
        "findings": findings,
        "observations": observations,
    }
    save_runtime_assessment(result)
    return result


def assess_network_alpha() -> Dict[str, Any]:
    return assess_environment(alpha_environment)


def assess_network_beta() -> Dict[str, Any]:
    return assess_environment(beta_environment)
