# Sensor (Sentinel)

**Status: not implemented.** This directory is a placeholder for the network sensor planned in
roadmap phase 4. There is no code here.

## Planned scope

A defensive sensor, built with Scapy or PyShark, that observes network **metadata and statistics**
(packets, bytes and connections per second, SYN and ACK rates, incomplete connections, destination
ports, protocol mix, source diversity) and reports them to the backend. It avoids storing application
payloads.

How the sensor talks to the backend (transport, authentication, batching) is not decided yet and will
be recorded in [../docs/architecture.md](../docs/architecture.md) before it is built.

## Safety

Run a sensor, and generate any test traffic, **only on networks you own or are explicitly authorised
to monitor**. Packet-capture permissions and behaviour differ by operating system and container
environment, so expect to need elevated privileges and some per-platform setup.

The detection design the sensor feeds is in [../docs/detection-engine.md](../docs/detection-engine.md)
(also not implemented).
