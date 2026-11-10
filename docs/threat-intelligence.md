# Threat intelligence (Intel)

> **Status: planned (Phase 2).** This page holds the principles the feature is built to. The detailed
> design, scoring method and provider behaviour are written here as the code lands.

## Intent

Let an analyst look up an indicator of compromise (IOC), see what each external provider says, and get
a CipherForge assessment whose reasoning is visible. Supported indicator types: IPv4, IPv6, domains,
URLs and SHA-256 hashes. First providers: AbuseIPDB and AlienVault OTX.

## Principles

- **Evidence, not truth.** A provider's answer is one input. Feeds can be stale, incomplete,
  contradictory or rate-limited.
- **Show each provider independently**, then the CipherForge correlation and score. Never label an
  indicator malicious from a single source.
- **Explainable scores.** Every score lists the evidence behind it, no single provider can dominate
  it, and the classification bands are fixed and documented: 0-20 Informational, 21-40 Low,
  41-60 Medium, 61-80 High and 81-100 Critical.
- **Say what is unknown.** Distinguish provider evidence from internal evidence, and show confidence,
  freshness and uncertainty. No reports does not mean safe.
- **One normalised indicator, many observations.** Raw provider observations stay traceable to their
  source and are never merged away.
- **The backend makes the calls.** Browsers never talk to a provider and never see an API key.
  Responses are cached with per-provider freshness rules, and every lookup is audited.
- **Geolocation is not attribution.** IP reputation and location do not identify a person or an
  attacker's whereabouts, and the UI must not suggest they do.
- **Recommend, never auto-block.** Suggested actions are advice for an analyst.

## Privacy and abuse considerations

Looking up an indicator sends it to a third party. The design is to reject private, loopback and
other non-public addresses before any provider is contacted, so internal addressing is not leaked and
the lookup cannot be used to make the server probe internal hosts. Provider terms of use and
free-tier limits apply; the platform must stay within them.

## What follows

Normalisation rules, provider adapters, the scoring methodology, caching and the audit record are
documented here once implemented. The related threats are tracked in [threat-model.md](threat-model.md).
