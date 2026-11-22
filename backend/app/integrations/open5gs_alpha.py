import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional


PROJECT_NAME = "susignal-network-alpha"
NETWORK_NAME = "Network Alpha"
NETWORK_DESCRIPTION = (
    "An isolated Open5GS v2.8.0 5G Core lab with HTTPS/mTLS SBI services."
)
NETWORK_FUNCTIONS = ("nrf", "amf", "smf", "upf", "ausf", "udm", "pcf", "udr")
SUPPORTING_SERVICES = ("mongodb",)
EXPECTED_SERVICES = NETWORK_FUNCTIONS + SUPPORTING_SERVICES


class EnvironmentManagerError(RuntimeError):
    pass


class Open5GSAlphaManager:
    project_name = PROJECT_NAME
    environment_id = "alpha"
    network_name = NETWORK_NAME
    network_description = NETWORK_DESCRIPTION
    network_functions = NETWORK_FUNCTIONS
    expected_services = EXPECTED_SERVICES
    compose_path_parts = ("deployments", "open5gs", "network-alpha", "compose.yaml")
    build_on_start = False

    def __init__(
        self,
        compose_file: Optional[Path] = None,
        wsl_distro: Optional[str] = None,
    ) -> None:
        repository_root = Path(__file__).resolve().parents[3]
        self.compose_file = Path(compose_file or (
            repository_root
            .joinpath(*self.compose_path_parts)
        )).resolve()
        self.wsl_distro = wsl_distro or os.environ.get(
            "SUSIGNAL_WSL_DISTRO", "Ubuntu"
        )

    def _wsl_compose_path(self) -> str:
        path = str(self.compose_file)
        match = re.match(r"^([A-Za-z]):[\\/](.*)$", path)
        if not match:
            raise EnvironmentManagerError(
                f"The {self.network_name} Compose file must be on a WSL-mounted "
                "Windows drive."
            )
        drive, remainder = match.groups()
        return f"/mnt/{drive.lower()}/{remainder.replace(chr(92), '/')}"

    def _command(self, arguments: List[str], compose: bool = True) -> List[str]:
        docker_path = shutil.which("docker")
        if docker_path:
            command = [docker_path]
        elif os.name == "nt":
            wsl_path = shutil.which("wsl.exe") or r"C:\Windows\System32\wsl.exe"
            if not Path(wsl_path).is_file():
                raise EnvironmentManagerError(
                    "Docker CLI is unavailable and WSL could not be found."
                )
            command = [
                wsl_path,
                "-d",
                self.wsl_distro,
                "--",
                "docker",
            ]
        else:
            raise EnvironmentManagerError(
                "Docker CLI is unavailable. Install Docker or configure the backend "
                "to access the Docker engine."
            )

        if compose:
            compose_path = (
                self._wsl_compose_path()
                if command[0].lower().endswith("wsl.exe")
                else str(self.compose_file)
            )
            command.extend([
                "compose",
                "--project-name",
                self.project_name,
                "--file",
                compose_path,
            ])
        command.extend(arguments)
        return command

    def _run(
        self,
        arguments: List[str],
        *,
        compose: bool = True,
        timeout: int = 30,
        allow_failure: bool = False,
    ) -> subprocess.CompletedProcess:
        command = self._command(arguments, compose=compose)
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise EnvironmentManagerError(
                f"Docker operation timed out after {timeout} seconds."
            ) from error
        except OSError as error:
            raise EnvironmentManagerError(
                f"Could not run the Docker operation: {error}"
            ) from error

        if result.returncode and not allow_failure:
            detail = (result.stderr or result.stdout or "").strip()
            if len(detail) > 800:
                detail = detail[-800:]
            raise EnvironmentManagerError(
                f"Docker Compose operation failed: {detail or 'unknown error'}"
            )
        return result

    @staticmethod
    def _parse_compose_rows(output: str) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for line in output.splitlines():
            if not line.strip():
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError as error:
                raise EnvironmentManagerError(
                    "Docker Compose returned an invalid service-status response."
                ) from error
            if isinstance(parsed, dict):
                rows.append(parsed)
            elif isinstance(parsed, list):
                rows.extend(item for item in parsed if isinstance(item, dict))
        return rows

    def _network_is_internal(self) -> Optional[bool]:
        result = self._run(
            [
                "network",
                "inspect",
                f"{self.project_name}_core",
                "--format",
                "{{.Internal}}",
            ],
            compose=False,
            allow_failure=True,
        )
        if result.returncode:
            return None
        value = result.stdout.strip().lower()
        return value == "true" if value in {"true", "false"} else None

    @staticmethod
    def _published_ports(row: Dict[str, Any]) -> List[Dict[str, Any]]:
        published_ports = []
        raw_labels = row.get("Labels") or ""
        if isinstance(raw_labels, dict):
            labels = raw_labels
        else:
            labels = {}
            for entry in str(raw_labels).split(","):
                name, separator, value = entry.partition("=")
                if separator:
                    labels[name.strip()] = value.strip()

        for publisher in row.get("Publishers") or []:
            try:
                port = int(publisher.get("PublishedPort") or 0)
            except (TypeError, ValueError):
                continue
            target_port = publisher.get("TargetPort")
            protocol = publisher.get("Protocol") or "tcp"
            host = publisher.get("URL")
            if not port and target_port:
                binding = labels.get(
                    f"desktop.docker.io/ports/{target_port}/{protocol}"
                )
                if binding:
                    label_host, separator, label_port = str(binding).rpartition(":")
                    try:
                        port = int(label_port) if separator else 0
                    except ValueError:
                        port = 0
                    host = label_host or host
            if port:
                published_ports.append({
                    "host": host or "0.0.0.0",
                    "host_port": port,
                    "target_port": target_port,
                    "protocol": protocol,
                })
        return published_ports

    def get_status(self) -> Dict[str, Any]:
        if not self.compose_file.is_file():
            raise EnvironmentManagerError(
                f"{self.network_name} Compose file was not found: {self.compose_file}"
            )

        result = self._run(["ps", "--all", "--format", "json"])
        rows = self._parse_compose_rows(result.stdout)
        by_service = {
            row.get("Service"): row
            for row in rows
            if row.get("Service") in self.expected_services
        }
        services = []
        for service_name in self.expected_services:
            row = by_service.get(service_name, {})
            state = str(row.get("State") or "missing").lower()
            health = str(row.get("Health") or "unknown").lower()
            services.append({
                "name": service_name,
                "kind": (
                    "network_function"
                    if service_name in self.network_functions
                    else "supporting_service"
                ),
                "state": state,
                "health": health,
                "container_id": row.get("ID"),
                "published_ports": self._published_ports(row),
            })

        running_count = sum(item["state"] == "running" for item in services)
        healthy_count = sum(item["health"] == "healthy" for item in services)
        if running_count == len(self.expected_services) and healthy_count == len(self.expected_services):
            status = "running"
        elif running_count:
            status = "degraded"
        elif not by_service:
            status = "not_created"
        else:
            status = "stopped"

        return {
            "id": self.environment_id,
            "name": self.network_name,
            "description": self.network_description,
            "status": status,
            "is_running": running_count > 0,
            "configured_network_functions": len(self.network_functions),
            "service_count": len(self.expected_services),
            "running_services": running_count,
            "healthy_services": healthy_count,
            "services": services,
            "network_internal": self._network_is_internal(),
        }

    def start(self) -> Dict[str, Any]:
        arguments = ["up", "--detach"]
        if self.build_on_start:
            arguments.append("--build")
        arguments.extend(["--wait", "--wait-timeout", "180"])
        self._run(arguments, timeout=300)
        return self.get_status()

    def stop(self) -> Dict[str, Any]:
        current = self.get_status()
        if not current["is_running"]:
            return current
        self._run(["stop"], timeout=90)
        return self.get_status()


alpha_environment = Open5GSAlphaManager()


class Open5GSBetaManager(Open5GSAlphaManager):
    project_name = "susignal-network-beta"
    environment_id = "beta"
    network_name = "Network Beta"
    network_description = (
        "An isolated NRF-only Open5GS lab with an intentionally loopback-published "
        "SBI port for runtime exposure testing."
    )
    network_functions = ("nrf",)
    expected_services = network_functions
    compose_path_parts = ("deployments", "open5gs", "network-beta", "compose.yaml")
    build_on_start = False


beta_environment = Open5GSBetaManager()
