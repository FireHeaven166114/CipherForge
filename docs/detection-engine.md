# Detection engine

> **Status: not implemented.** This page records the intended design from the project specification
> (Sentinel, Core and the mini-SIEM, roadmap phases 4 to 7) so the later code has something to be
> checked against. Nothing described here exists in the codebase yet. The only scoring that exists
> is for threat-intelligence indicators (Phase 2, built); see
> [threat-intelligence.md](threat-intelligence.md).

## Intent

Observe network metadata and application events, turn them into a common event model, run
configurable rules and baselines against them, and raise **explainable** alerts that an analyst
reviews. Detection and response stay separate: the system recommends, a person decides.

## Planned signals (Sentinel)

Defensive monitoring of metadata and statistics rather than stored payloads: packets, bytes and
connections per second, requests per second where observable, unique source and destination
addresses, TCP SYN and ACK rates, incomplete connections, destination ports, protocol distribution
and source diversity.

No single fixed threshold is enough, because high traffic does not by itself mean an attack. Load
tests, defects, crawlers, NAT gateways, backups and ordinary spikes can look hostile. The plan is to
combine:

- request-rate deviation against a rolling baseline;
- a SYN-flood indicator (many SYNs with few completed handshakes);
- traffic-volume anomalies;
- source diversity (concentrated versus distributed);
- repetition, so sustained behaviour matters more than a brief spike.

## Baselines

Start with simple, explainable statistics: rolling averages, configurable percentiles, standard
deviation, EWMA and z-score style deviation. Machine learning is deliberately out of scope until
those are understood and measured.

## Rules and events

Different observations are normalised into one security-event model, and rules run against that
model. Candidate rules: possible DoS or SYN flood, a known-malicious indicator observed, repeated
authentication failures, a suspicious file hash, repeated unauthorised file access, honeypot
interaction and a threat-intelligence match. Rule logic belongs in `backend/app/detection/`, not in
controllers or UI code.

## Correlation

A network anomaly extracts its source indicator, looks it up (cache first), combines the external
evidence with internal evidence and produces an explainable score. External reputation **enriches**
detection and never gates it: a high-confidence internal anomaly matters even when no feed has seen
the source.

The lookup half exists: the Phase 2 investigation service already normalises an indicator, answers
from its stored results when they are fresh, queries the providers otherwise and scores the result
with the `intel-risk-v1` method (see [threat-intelligence.md](threat-intelligence.md)). It reports
`internal_evidence` as unavailable today. Combining it with internal events is the planned work.

## Alerts

Planned fields: `alert_id`, `alert_type`, `severity`, `source`, `destination`, `timestamp`,
`risk_score`, `confidence`, `description`, `evidence`, `mitre_technique` and `status`
(New, Investigating, Resolved, False Positive) with an assignee. An alert keeps the evidence and
correlation identifiers needed to reconstruct why it fired. A MITRE ATT&CK technique is attached only
where the evidence supports one (for example, password guessing and T1110 Brute Force).

## Language and limits

- Use conservative wording: "suspected DoS activity", "possible SYN flood", "anomalous source",
  "unusual connection rate". The platform never claims to identify a perpetrator.
- Expect false positives during legitimate spikes; the design leans on baselines, several signals and
  analyst review.
- No automatic blocking. Any future response playbook is a lab feature that needs analyst approval.
- Sensors and test traffic are only for authorised environments. See [../sensor/README.md](../sensor/README.md).
