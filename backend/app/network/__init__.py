"""Network monitoring: packet capture, flow aggregation and detection over real traffic.

Packets come from a live capture (Scapy over Npcap on Windows, libpcap or the kernel's packet
socket elsewhere) or from an uploaded PCAP/PCAPNG file. Only packet metadata is kept (addresses,
ports, protocol, sizes, timestamps, TCP flags). Packet payloads are never stored or logged.

Layout:

* ``packets``    - reduce a captured packet to ``PacketMeta``.
* ``windows``    - bounded sliding-window counters used by the detection rules.
* ``flows``      - bidirectional flow aggregation with expiry and a size limit.
* ``analyzer``   - flows + detection rules + statistics for one monitoring session.
* ``pcap``       - validate and read capture files.
* ``capture``    - interface discovery and the live-capture machinery.
* ``recorder``   - persists a session's flows, alerts and totals.
* ``enrichment`` - looks up public addresses with the threat-intelligence providers.
* ``service``    - the use cases behind ``/api/v1/network``.

The detection rules themselves live in ``app.detection.network_rules``.
"""
