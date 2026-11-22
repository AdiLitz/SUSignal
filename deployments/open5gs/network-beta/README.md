# Network Beta: loopback exposure assessment lab

Network Beta is a small, isolated Open5GS NRF test environment for demonstrating runtime exposure findings. It reuses the locally built Open5GS 2.8.0 image and NRF configuration from Network Alpha, but runs under its own Compose project and certificate volumes.

The NRF SBI port is deliberately published only on `127.0.0.1:17777`. The Docker network remains internal, and the port is not bound to a LAN or public interface. SUSignal's runtime assessment reports this host-loopback publication as a medium-severity finding because processes on the host can reach the listener.

Start and assess Beta from SUSignal's **5G Test Environments** page. The backend uses fixed Docker Compose operations; it does not expose arbitrary shell commands or Docker access to the browser. Stop Beta from that page when finished.
