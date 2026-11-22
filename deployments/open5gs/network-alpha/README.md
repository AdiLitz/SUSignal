# Network Alpha: isolated Open5GS lab

This Compose project is the first deployable SUSignal test environment. It runs Open5GS v2.8.0 Network Functions in separate containers on a private Docker network, with a dedicated MongoDB instance and persistent project-scoped volumes.

The core includes AMF, SMF, UPF, NRF, AUSF, UDM, PCF, and the supporting UDR. SBI links use locally generated TLS certificates with client certificate verification. NAS security preferences are limited to NIA2 and NEA2. No service ports are published to the host.

The locally generated CA and certificates are for this isolated lab only; they are not a production PKI.

This is a core-network lab, not an end-to-end mobile network: no gNB, UE, RF access, or subscriber provisioning is included. Healthy SBI services pass a process check and mutual-TLS listener check; UPF health is process-level. These checks do not prove UE connectivity or every NF service procedure.

## Requirements

- Docker Desktop with the WSL2 backend and Docker Compose v2.
- WSL2 Ubuntu with `/dev/net/tun` available.
- Internet access for the first image build and MongoDB image pull.
- Up to 2 GiB of configured memory limits while the environment is running, plus 128 MiB for one-shot certificate setup. Actual use is lower. Only this one environment is started.

The Open5GS image uses the Ubuntu 26.04 Open5GS PPA package pinned to `2.8.0~resolute6`; the MongoDB image is pinned to the `8.0` series.

## Start, inspect, and stop

From WSL Ubuntu:

```bash
cd /mnt/c/Bits2Wave/deployments/open5gs/network-alpha
docker compose up -d --build --wait
docker compose ps
docker compose logs --tail=80
docker compose stop
```

`stop` preserves the environment's MongoDB and locally generated certificate volumes. Do not use `docker compose down -v` if you want to retain them.

The network is internal to Docker, and no ports are exposed to the host. This environment is not yet wired to SUSignal's environment-management API or runtime scanner; those are later implementation stages.
