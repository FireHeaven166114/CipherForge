# Detection engine

Part of [CipherForge](../README.md). Related pages: [network-monitoring.md](network-monitoring.md)
for capture, flows, enrichment and privacy, [threat-intelligence.md](threat-intelligence.md) for the
scoring that NET-005 relies on, [api.md](api.md) for the endpoints and
[architecture.md](architecture.md) for where the engine sits.

The detection engine that exists today is the **network rule set**: seven rules, NET-001 to NET-007,
that run over the traffic of one monitoring session and raise alerts an analyst can read and check.
It is deliberately simple. Each rule counts one kind of behaviour by one source address over a
sliding time window and compares the count with a threshold. The alert records what was counted, the
threshold, the window and the addresses involved, so you can see why it fired and how far past the
threshold the activity went.

The wider design from the original project plan (baselines, a common event model, correlation with
application events, an alert workflow) is **not built**. It is kept at the end of this page under
[Planned and not implemented](#planned-and-not-implemented) so it is not mistaken for a feature.

## At a glance

| | |
| --- | --- |
| Rules | NET-001 to NET-007, in `backend/app/detection/network_rules.py`. |
| Runs on | Packet metadata only: time, addresses, ports, protocol, size and TCP flags, from a live capture or an uploaded PCAP/PCAPNG file. Never payloads. |
| Method | Fixed thresholds over sliding windows, counted per source address. No baseline and no learning. |
| Output | Rows in `network_alerts`: rule, severity, observed value against threshold, a plain-language explanation (times in IST), evidence and the enrichment state of the addresses involved. |
| Decides | Nothing beyond raising the alert. No traffic is blocked, and an alert never changes an indicator's risk score. |
| Configured by | Environment variables (see [Thresholds and settings](#thresholds-and-settings)). `GET /api/v1/network/rules` shows the values in force. |

The default thresholds are starting points for a lab or a demonstration, not security standards.
Every real network needs them tuned (see [Tuning](#tuning)).

## How a packet is judged

Packets reach the rule engine one at a time, in capture order. The engine takes "now" from the
packet's own timestamp, not from the server clock, so replaying a capture file gives the same alerts
every time, and a file recorded last month is judged on its own timeline.

Which rules see which packets:

| Packet | Rules that look at it |
| --- | --- |
| Any IP packet | NET-007 (is the protocol expected?) and NET-004 (adds the packet size to the sender's volume). |
| TCP packet with SYN set and ACK clear (a "pure SYN") | NET-003, which counts it, retransmissions included. |
| First packet of a **new flow** that can start a connection | NET-002, which counts it. If the packet has a destination port, also NET-001 (records the port); if that port is on the suspicious-port list, also NET-006. |
| A public address, once it has been looked up | NET-005. This one is not driven by packets; see [NET-005](#net-005-known-malicious-address). |

"Can start a connection" means a TCP packet with the ACK bit clear (a SYN, or the flag-less and FIN
probes that port scanners send) or any non-TCP packet. A TCP packet with ACK set belongs to a
connection that was already under way, such as a reply or a capture that started in the middle, so
it is not an attempt. A flow is "new" when the flow table had no active flow for the same two
address/port pairs and protocol (see [Flows](network-monitoring.md#flows)).

Anything that is not IP (ARP, spanning tree) never reaches the rules. It is only counted. See
[network-monitoring.md](network-monitoring.md#how-it-works).

### Sliding windows

Each rule keeps a counter per source address (`SlidingWindow` in `backend/app/network/windows.py`).
A counter stores events in one-second buckets and discards buckets older than the window.

- The window edge is accurate to one second.
- A packet that arrives out of order is counted in the newest second. A packet older than the whole
  window is ignored.
- Each counter is capped (at least 2,048 distinct second/key entries). Past the cap the oldest
  seconds are dropped and the alert evidence says `"truncated": true`. A flood can therefore be
  under-counted, but memory cannot grow without limit.
- The engine remembers the most recently active sources only: the larger of 1,000 and
  `MAX_ACTIVE_FLOWS` (10,000 by default). The least recently active source is forgotten first, and
  forgetting a source resets its counters.

### Severity

An alert is raised when a measurement reaches its threshold. Its severity then depends on how far
past the threshold the measurement is: at 1x, 3x and 10x the threshold.

| Rule | 1x | 3x | 10x |
| --- | --- | --- | --- |
| NET-001 port scan | medium | high | critical |
| NET-002 connection rate | low | medium | high |
| NET-003 SYN rate | medium | high | critical |
| NET-004 high volume | low | medium | high |
| NET-005 known malicious address | high, or critical when the address is classified critical (score 81 to 100) | | |
| NET-006 suspicious port | medium | high | high |
| NET-007 unexpected protocol | low (always) | | |

### Staying quiet, and escalating

Once a rule has fired for a source it stays quiet for one window, so one scan is one alert and not
one alert per packet. There is one exception: if the measurement later reaches the next severity
step (3x or 10x the threshold), another alert is raised, so a growing attack is not hidden behind its
first alert. When the window has passed, a source that is still above the threshold alerts again.

Two caps keep a noisy session from filling the database: 500 alerts per session and 200 per rule.
Alerts beyond a cap are not stored; they are counted in `alerts_suppressed`, which the session detail
shows. A suppressed burst is counted once per window and source, not once per packet. The caps are
constants in `NetworkRuleConfig`, not settings.

NET-005 alerts are created by the enrichment worker, not by the rule engine, so these caps do not
apply to them. They are limited to one alert per address per session instead.

## The rules

| Rule | Name | Counts | Default threshold | Default window |
| --- | --- | --- | --- | --- |
| NET-001 | `port_scan` | Distinct destination ports tried by one source | 20 ports | 60 s |
| NET-002 | `connection_rate` | New flows opened by one source | 100 flows | 60 s |
| NET-003 | `syn_rate` | Pure SYN packets sent by one source | 200 packets | 10 s |
| NET-004 | `high_volume` | Bytes sent by one source | 50 MB | 60 s |
| NET-005 | `known_malicious_ip` | Risk score of a looked-up public address | score 61 | none |
| NET-006 | `suspicious_port` | New flows from one source to a listed port | 25 attempts | 60 s |
| NET-007 | `unexpected_protocol` | The first packet of a protocol that is not expected | 1 | none |

Each rule below says what it counts, what the alert contains, and what commonly makes it fire for
harmless reasons. Evidence fields are the keys of the alert's `evidence` object.

### NET-001 port scan

**Counts** the distinct destination ports (TCP, UDP and SCTP) that one source tried in new flows
within the window. Trying the same port again and again does not raise the count. Packets of
connections that are already established are not counted. The ports are counted across all
destinations, so one host touching 20 different services on 20 different machines looks the same as a
scan of one machine. The alert says how many hosts were involved, and `dst_ip` is set only when
there was exactly one.

**Evidence:** `unique_ports`, `sample_ports` (the lowest 20 port numbers seen), `unique_targets`,
`top_targets` (up to five addresses with their attempt counts), `truncated`.

**Harmless causes:** an authorised vulnerability or inventory scanner, some peer-to-peer programs,
service-discovery tools, a monitoring server that polls many services.

**Misses:** slow scans that stay under the threshold in every window, and scans that are shared out
over several source addresses, because the counters are per source.

### NET-002 connection rate

**Counts** new flows opened by one source within the window, for every protocol. Each new
combination of addresses and ports is a new flow, so a UDP client that uses a fresh source port for
every query adds one per query.

**Evidence:** `new_flows`, `unique_destinations`, `top_destinations` (up to five addresses with
counts), `truncated`. `dst_ip` is set only when there was one destination.

**Harmless causes:** DNS resolvers, NAT gateways and proxies (many users behind one address), load
tests, crawlers, backup and monitoring jobs.

### NET-003 SYN rate

**Counts** TCP packets with SYN set and ACK clear that one source sent within the window. Repeated
SYNs (retransmissions) count. SYN-ACKs sent by a busy server are not counted. The rule does not
check whether the handshakes complete, so it cannot tell a SYN flood from a client that is simply
very busy.

**Evidence:** `syn_packets`, `unique_destinations`, `top_destinations`, `truncated`. `dst_port` is
the port of the packet that crossed the threshold.

**Harmless causes:** the first seconds of a load test, a crawler, a browser opening many
connections. A fast port scan raises this rule together with NET-001 and NET-002; the alerts are
separate and are not grouped.

### NET-004 high volume

**Counts** the bytes one source sent within the window: the packet length as seen on the wire,
headers included. Bytes a host receives do not count against it. "MB" here is 1,048,576 bytes.

**Evidence:** `bytes`, `unique_destinations`, `top_destinations` (address and bytes), `truncated`.
The alert's `observed_value` is in MB, rounded to two decimals. The severity never goes above high.

**Harmless causes:** backups, software updates, video, large file transfers. On a capture taken at one
host, a big download counts against the remote server, because that server is the source of the
bytes.

### NET-005 known malicious address

This rule is not driven by packets. After the enrichment worker has looked up a public address (see
[External IP enrichment](network-monitoring.md#external-ip-enrichment)) and at least one provider
returned evidence, the address's existing risk score is compared with `KNOWN_MALICIOUS_MIN_SCORE`
(default 61, the bottom of the "high" band). At or above it, one alert is raised for that address in
that session.

- It adds no score of its own. The number is the `intel-risk-v1` score the Investigate page shows for
  the same address (see [threat-intelligence.md](threat-intelligence.md)).
- "No data" is never treated as a verdict. A lookup where no provider returned evidence is not
  assessed and cannot raise the alert.
- It needs enrichment. With `EXTERNAL_ENRICHMENT_ENABLED=false`, with no provider key configured, for
  addresses beyond the per-session lookup budget (`NETWORK_ENRICHMENT_MAX_IPS`), and for private or
  reserved addresses, it cannot fire. `GET /api/v1/network/rules` reports it as inactive when
  enrichment is switched off.
- Severity is critical when the address is classified critical (score 81 to 100) and high
  otherwise. If you set the minimum below 61, addresses in the lower bands also raise high alerts.
- The alert appears when the lookup finishes, which can be a while after the traffic: lookups are
  paced (`NETWORK_ENRICHMENT_MAX_PER_MINUTE`, default 4). `first_observed` and `last_observed`
  describe the traffic and `created_at` says when the alert was raised.
- If the monitored hosts sent traffic to the address, the address is the alert's `dst_ip` and the
  first peer is the `src_ip`. If they only received traffic from it, the address is the `src_ip`.

**Evidence:** `address`, `risk_score`, `classification`, `providers` (the providers that answered,
with their status and verdict), `peers`, `ports`, `protocols`, `packets`, `bytes`.

### NET-006 suspicious port

**Counts** new flows from one source to any port on the suspicious-port list, summed over the
listed ports, within the window. The default list is 23 (Telnet), 135 (Windows RPC), 139 and 445
(Windows file sharing), 1433 (SQL Server), 3389 (Remote Desktop), 4444, 5900 (VNC), 6667 (IRC) and
31337. These are ports of services that are often attacked or abused. They are not malicious by
themselves.

**Evidence:** `attempts`, `unique_ports`, `by_port` (the ten most attempted ports), `truncated`. The
alert's `dst_port` is the most attempted port. The severity never goes above high.

**Harmless causes:** normal file sharing and remote administration inside an office or lab network.
Expect this rule to be noisy on Windows networks until you adjust the list.

### NET-007 unexpected protocol

**Raises** one low-severity alert for the first packet of each protocol, source and destination
combination whose IP protocol is not on the expected list. It has no threshold or window: the
threshold is 1. The default expected list is `tcp`, `udp`, `icmp`, `icmpv6` and `igmp`. The names
the engine knows are those, plus `gre`, `esp`, `ah`, `ospf` and `sctp`; any other protocol number
appears as `proto-<number>`.

**Evidence:** `protocol`, `expected_protocols`.

**Harmless causes:** VPN traffic (ESP, GRE), routing protocols (OSPF), SCTP. Add the protocol to
`EXPECTED_PROTOCOLS` when it is normal on your network.

## What an alert looks like

Analysing the sample capture in `frontend/e2e/data/synthetic-network.pcap` (synthetic traffic made by
`backend/devtools/synthetic_network.py`, not a recording of a real network) with the default
settings produces, among others, this NET-001 alert for the documentation address `203.0.113.77`:

```text
explanation: 203.0.113.77 tried 20 different destination ports on 1 host within 60 seconds
             (threshold: 20 ports), between 11-06-2025 04:00:02 PM IST and
             11-06-2025 04:00:03 PM IST.
severity:    medium
observed_value / threshold / unit / window_seconds:  20 / 20 / ports / 60
evidence:    {"unique_ports": 20, "sample_ports": [3000, 3001, ... 3019], "unique_targets": 1,
              "top_targets": [{"address": "10.20.30.40", "count": 20}], "truncated": false}
```

The alert fires at the 20th distinct port. The scanner in that file keeps going, but the rule stays
quiet for the rest of the window and the count never reaches 3x.

### Alert fields

The fields come from `AlertOut` in `backend/app/schemas/network.py`.

| Field | Meaning |
| --- | --- |
| `id`, `session_id` | The alert and the monitoring session it belongs to. |
| `rule_id`, `rule_name`, `title` | For example `NET-001`, `port_scan`, "Port scan". |
| `severity` | `low`, `medium`, `high` or `critical`. |
| `explanation` | One sentence saying what was seen, in plain language. Times in it are IST. |
| `observed_value`, `threshold`, `unit`, `window_seconds` | What was measured, what it was compared with, what the unit is and the window (null for NET-005 and NET-007). |
| `src_ip`, `dst_ip`, `dst_port`, `protocol` | The addresses and port involved, when one is clear. They are null when the finding covers several. |
| `first_observed`, `last_observed` | The span of the traffic that caused the alert, from packet timestamps. |
| `created_at` | When CipherForge stored the alert. |
| `evidence` | The rule-specific object described above. |
| `enrichment` | The lookup state of the public address the alert is about (see [network-monitoring.md](network-monitoring.md#external-ip-enrichment)). |

API timestamps are UTC (ISO-8601); the `explanation` text and the dashboard show IST (see
[Time handling](architecture.md#time-handling-utc-storage-ist-display)). The alert says "suspected"
behaviour in the sense that it reports a measurement, not an intention. It does not identify a
person, and a spoofed source address cannot be told apart from a real one.

There is no alert status, assignee or note yet. An alert cannot be acknowledged, closed or marked as
a false positive; it stays until its session is deleted or expires (see
[Retention and deletion](network-monitoring.md#retention-and-deletion)).

## Thresholds and settings

All rule settings are read from the environment when the API starts, so changing one needs a
restart. They are listed in `.env.example`, and `backend/tests/test_deployment_files.py` checks that
every setting appears in both `.env.example` and `docker-compose.yml`. Out-of-range values stop the
application from starting with a message that names the setting.

| Setting | Default | Allowed | Rule |
| --- | --- | --- | --- |
| `PORT_SCAN_THRESHOLD` | 20 | 2 to 65,535 | NET-001 |
| `PORT_SCAN_WINDOW_SECONDS` | 60 | 1 to 3,600 | NET-001 |
| `CONNECTION_RATE_THRESHOLD` | 100 | 2 to 1,000,000 | NET-002 |
| `CONNECTION_RATE_WINDOW_SECONDS` | 60 | 1 to 3,600 | NET-002 |
| `SYN_RATE_THRESHOLD` | 200 | 2 to 10,000,000 | NET-003 |
| `SYN_RATE_WINDOW_SECONDS` | 10 | 1 to 3,600 | NET-003 |
| `HIGH_VOLUME_THRESHOLD_MB` | 50 | 1 to 1,000,000 | NET-004 |
| `HIGH_VOLUME_WINDOW_SECONDS` | 60 | 1 to 3,600 | NET-004 |
| `KNOWN_MALICIOUS_MIN_SCORE` | 61 | 1 to 100 | NET-005 |
| `SUSPICIOUS_PORT_THRESHOLD` | 25 | 2 to 1,000,000 | NET-006 |
| `SUSPICIOUS_PORT_WINDOW_SECONDS` | 60 | 1 to 3,600 | NET-006 |
| `SUSPICIOUS_PORTS` | `23,135,139,445,1433,3389,4444,5900,6667,31337` | comma-separated ports, 1 to 65,535 | NET-006 |
| `EXPECTED_PROTOCOLS` | `tcp,udp,icmp,icmpv6,igmp` | at least one comma-separated name, made lower-case on load; letters, digits and hyphens, up to 16 characters | NET-007 |

Settings that shape the whole module rather than one rule, such as `MAX_ACTIVE_FLOWS`,
`FLOW_IDLE_TIMEOUT_SECONDS`, `NETWORK_RETENTION_HOURS` and the enrichment limits, are described in
[network-monitoring.md](network-monitoring.md) and [setup.md](setup.md#environment-variables).

Rules cannot be added, edited or switched off at run time, and there is no per-rule disable setting.
The only switch that affects a rule is `EXTERNAL_ENRICHMENT_ENABLED`, which stops NET-005.

### Tuning

Replaying a capture is deterministic, so you can tune on a file instead of on live traffic:

1. Analyse a capture of traffic you know is normal, with the defaults.
2. Read the alerts that fire. Each one shows the observed value next to the threshold, so you can
   see how far normal activity goes. To see where a quiet rule would sit, lower its threshold and
   analyse the same file again.
3. Raise a threshold (or add a protocol to `EXPECTED_PROTOCOLS`, or remove a port from
   `SUSPICIOUS_PORTS`) when a rule fires on activity you know is harmless. Lower it for earlier
   warning at the price of more false alarms.
4. Restart the API and analyse the same file again to confirm the effect.

## Limitations

- **Fixed thresholds.** There is no baseline, so a quiet network and a busy one use the same
  numbers until you change them.
- **Per-source counting.** Activity spread over many source addresses (a distributed scan, or a
  host that rotates IPv6 addresses) is not added up. Many users behind one NAT address are added up
  and can look like one noisy host.
- **Short memory.** Only the current window is considered. A slow scan that stays under the
  threshold in every window is not seen, and nothing is learned between sessions.
- **No payload inspection.** There are no signatures, no protocol parsing above TCP/UDP/SCTP and no
  TLS inspection. This is not an intrusion detection system.
- **What the capture sees.** A live capture without promiscuous mode sees the traffic of the machine
  that runs the API, not the whole network. See [network-monitoring.md](network-monitoring.md).
- **Approximate windows.** Window edges are one second wide, and a counter that hits its cap
  under-counts (the alert says `truncated`).
- **NET-005 depends on providers.** It sees only what the configured providers know, only for
  addresses that were looked up, and only after the lookup finishes. Without a key for any provider
  it never fires.
- **No correlation.** Alerts from different rules about the same behaviour are separate. Nothing
  combines network alerts with the application's own events.
- **Internal evidence on the Investigate page stays "unavailable".** The investigation service
  still reports that no internal telemetry is connected, even though network sessions exist. Showing
  a network sighting next to an indicator is planned work.

## How it is tested

The rules are plain functions of packet metadata, so they are tested without a network: the tests in
`backend/tests/test_network_rules.py` feed synthetic packets and check the threshold edge (the
value just below and at the threshold), that established connections are not counted, window
expiry, one alert per window with escalation at 3x and 10x, per-source isolation, replay
determinism, configurable thresholds, the caps and the bounded memory. Window and flow behaviour is
covered in `test_network_windows_flows.py`, session statistics and peer tracking in
`test_network_analyzer.py`, and NET-005 (the minimum score, severity, one alert per address, and no
alert for a low score) in `test_network_enrichment.py`. How to run them is in
[testing.md](testing.md).

## Planned and not implemented

The original design aimed at more than fixed thresholds. None of the following exists in the code.
It is kept here so the later work can be checked against it.

**Intent.** Observe network metadata and application events, turn them into a common event model,
run configurable rules and baselines against them, and raise **explainable** alerts that an analyst
reviews. Detection and response stay separate: the system recommends, a person decides.

**Signals.** Defensive monitoring of metadata and statistics rather than stored payloads. No single
fixed threshold is enough, because high traffic does not by itself mean an attack: load tests,
defects, crawlers, NAT gateways, backups and ordinary spikes can look hostile. The plan was to
combine several signals, and this is how far each one has got:

| Planned signal | Today |
| --- | --- |
| Request-rate deviation against a rolling baseline | Not built. NET-002 and NET-003 use fixed thresholds. |
| SYN-flood indicator: many SYNs with few completed handshakes | Partly. NET-003 counts SYNs; it does not look at whether handshakes complete. |
| Traffic-volume anomalies | Partly. NET-004 uses a fixed threshold per source. |
| Source diversity: concentrated versus distributed | Not built. Counters are per source address. |
| Repetition: sustained behaviour matters more than a brief spike | Not built as a signal. A rule re-alerts after a quiet window and at 3x and 10x. |
| Protocol distribution | Counted per session and shown, but only NET-007 judges it. |
| Packets, bytes and connections per second, unique sources and destinations, incomplete connections | Session totals and top talkers are kept; no rule uses incomplete connections. |

**Baselines.** Start with simple, explainable statistics: rolling averages, configurable
percentiles, standard deviation, EWMA and z-score style deviation. Machine learning is deliberately
out of scope until those are understood and measured.

**A common event model and more rules.** Different observations (network metadata, authentication
events, file activity, honeypot hits) normalised into one security-event model, with rules over that
model. Candidate rules: possible DoS or SYN flood, a known-malicious indicator observed, repeated
authentication failures, a suspicious file hash, repeated unauthorised file access, honeypot
interaction and a threat-intelligence match. Today the network rules read packet metadata directly.
The file-sharing module writes audit events such as rejected downloads (see
[file-sharing.md](file-sharing.md#audit-events)), but nothing raises an alert from them. Rule logic
stays in `backend/app/detection/`, not in controllers or UI code, as the network rules already do.

**Correlation with internal evidence.** A network anomaly extracts its source indicator, looks it
up (cache first), combines the external evidence with internal evidence and produces an explainable
score. External reputation **enriches** detection and never gates it: a high-confidence internal
anomaly matters even when no feed has seen the source. What exists is the lookup half: the
investigation service normalises an indicator, answers from stored results when they are fresh,
queries the providers otherwise and scores the result with `intel-risk-v1`. The six traffic rules
(NET-001 to NET-004, NET-006 and NET-007) do not depend on any provider. NET-005 is the one rule that
exists because of external reputation. No combined score is produced; the alert's severity comes
from its rule and the lookup result is shown beside it.

**Alert workflow.** Planned fields: `alert_id`, `alert_type`, `severity`, `source`, `destination`,
`timestamp`, `risk_score`, `confidence`, `description`, `evidence`, `mitre_technique` and `status`
(New, Investigating, Resolved, False Positive) with an assignee. An alert keeps the evidence and
correlation identifiers needed to reconstruct why it fired. A MITRE ATT&CK technique is attached
only where the evidence supports one (for example, password guessing and T1110 Brute Force).

| Planned alert field | Today |
| --- | --- |
| `alert_id`, `alert_type` | `id`, `rule_id` and `rule_name`. |
| `severity`, `source`, `destination`, `timestamp` | `severity`, `src_ip`, `dst_ip`, `first_observed`, `last_observed` and `created_at`. |
| `risk_score` | Only inside the enrichment of the address the alert is about; there is no alert-level score. |
| `description`, `evidence` | `explanation` and `evidence`. |
| `confidence`, `mitre_technique` | Not built. No rule carries a MITRE ATT&CK technique. |
| `status`, assignee | Not built. |

**Language and limits.**

- Use conservative wording: "suspected DoS activity", "possible SYN flood", "anomalous source",
  "unusual connection rate". The platform never claims to identify a perpetrator.
- Expect false positives during legitimate spikes; the design leans on baselines, several signals and
  analyst review.
- No automatic blocking. Any future response playbook is a lab feature that needs analyst approval.
- Sensors and test traffic are only for authorised environments. A separate remote sensor
  ("Sentinel") is planned but not built; the monitoring that exists runs inside the API process on
  the machine that hosts it. See [../sensor/README.md](../sensor/README.md).

## Where the code is

| File | What it holds |
| --- | --- |
| `backend/app/detection/network_rules.py` | `RuleInfo` for each rule, `NetworkRuleConfig`, `RuleEngine` (NET-001 to NET-004, NET-006, NET-007), `known_malicious_alert` (NET-005), `describe_rules`. |
| `backend/app/network/windows.py` | `SlidingWindow` and `LruMap`, the bounded counters. |
| `backend/app/network/packets.py` | `PacketMeta`, including `is_pure_syn` and `opens_connection`. |
| `backend/app/network/flows.py` | The flow table that decides whether a packet starts a new flow. |
| `backend/app/network/analyzer.py` | Feeds each packet to the flow table and the rules, and tracks public peers. |
| `backend/app/network/enrichment.py` | The worker that looks addresses up and raises NET-005. |
| `backend/app/core/config.py` | The settings above and their validation. |
| `backend/tests/test_network_rules.py` | Rule tests. |
