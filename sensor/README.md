# Sensor (Sentinel)

**Status: the separate sensor is not implemented.** This directory is a placeholder for a standalone
network sensor that would run on another machine and report to the backend. It belongs to the phases
after Phase 4 (5 to 12 in [project-status.md](../docs/project-status.md)), which have not been
started: Phase 4 built the network monitor inside the API process instead. There is no code here.

Network monitoring itself **does exist**, inside the API process. The backend can capture packets on
the machine that runs it, or analyse an uploaded capture file, build flows and apply the
NET-001 to NET-007 rules. That module is documented in
[../docs/network-monitoring.md](../docs/network-monitoring.md) and
[../docs/detection-engine.md](../docs/detection-engine.md), and its code is in `backend/app/network/`.
What is missing is the remote half: a sensor that watches a different host or network segment and
sends its metadata to the backend.

## Planned scope

A defensive sensor, built with Scapy or PyShark (the in-process monitor already uses Scapy), that
observes network **metadata and statistics** (packets, bytes and connections per second, SYN and ACK
rates, incomplete connections, destination ports, protocol mix, source diversity) and reports them to
the backend. It avoids storing application payloads.

How the sensor talks to the backend (transport, authentication, batching) is not decided yet and will
be recorded in [../docs/architecture.md](../docs/architecture.md) before it is built.

## Safety

Run a sensor, and generate any test traffic, **only on networks you own or are explicitly authorised
to monitor**. Packet-capture permissions and behaviour differ by operating system and container
environment, so expect some per-platform setup and, on Linux, root or the `CAP_NET_RAW` capability.
The capture requirements of the existing in-process monitor (Npcap on Windows, libpcap on Linux,
[privileges](../docs/network-monitoring.md#privileges), containers) are in
[../docs/network-monitoring.md](../docs/network-monitoring.md#requirements).

The rules a sensor's data would feed are in
[../docs/detection-engine.md](../docs/detection-engine.md). Baselines and correlation with other
events, which the sensor design assumed, are listed there as planned and are not built.
