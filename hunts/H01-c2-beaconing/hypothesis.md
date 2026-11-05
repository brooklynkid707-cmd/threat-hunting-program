# H01 - C2 beaconing to unsanctioned external destinations

PEAK type: **hypothesis-driven** | ATT&CK: **T1071.001** Application Layer Protocol: Web Protocols (also T1573 Encrypted Channel) | Status: **closed - baseline documented, no detection**

## Prepare

**Hypothesis.** An endpoint at Northwind is running an implant that checks in to its C2 over HTTPS on a fixed sleep with jitter (current commodity loaders seen in logistics-sector phishing default to a ~5-minute sleep and 10-30% jitter). If so, one (host, external domain) pair will have inter-arrival times that cluster tightly around a central value, a stable small payload size, and a destination that is not in the software inventory.

**Why this hypothesis now.** Threat intel (backlog priority 20): loader families delivered by invoice-themed phishing to freight and logistics firms this quarter. Our proxy data has 14 days of retention and full destination coverage.

**Data sources.** Proxy / outbound connection logs (`network`): timestamp, host, user, destination domain and IP, port, bytes out/in, user agent. Software inventory (`hunt/inventory.py`) for sanctioned beacon-like destinations.

**Assumptions.**
- The implant uses a sleep timer, not purely event-driven traffic. A human-operated session with no sleep would not show up here.
- Jitter is bounded (< ~50%) and the implant runs long enough for at least 20 check-ins to accumulate.
- Proxy timestamps are accurate to the second, and NAT does not collapse hosts into one source.
- Sanctioned software that beacons is listed in the inventory. An unlisted legitimate agent is a real false-positive risk, so every suppression is shown to the analyst.

**Scope.** All 63 hosts with proxy telemetry, 14 days (2026-09-07 to 2026-09-20), external destinations only (internal `*.northwind.example` and RFC 1918 out of scope). Minimum 20 connections per pair.

**Why simple frequency fails (stated before execution).** Ranking pairs by connection count, or alerting on "more than N connections per hour", surfaces the chattiest software, not the most regular. The event-driven file-sync client makes thousands of connections a day and a low-and-slow implant only ~288. The hunt therefore measures interval *shape*, not volume.

## Execute

**Method.** `hunt/hunts/h01_beaconing.py` (production equivalents: `query.kql`, `query.spl`).

1. Group outbound connections by (host, destination domain). Drop internal destinations.
2. Sort timestamps and compute inter-arrival deltas.
3. Per pair, compute: connection count; median interval; classic coefficient of variation `CV = stdev/mean`; **robust CV** `1.4826 x MAD / median`, so a single overnight gap or missed check-in does not wreck the score; **in-band fraction**, the share of deltas within +/-30% of the median (a 20%-jitter beacon puts almost all of them in band); and CV of bytes_out.
4. Score 0-100: regularity from the robust CV, weighted by in-band fraction, payload stability and volume, and gated to a plausible beacon band (30 s - 2 h median).
5. Multiply destinations in the software inventory by 0.05. They stay in the output with the reason recorded and are reviewed rather than silently dropped.
6. For contrast, run the naive connection-count ranking over the same data.

**Execution notes.** 559 (host, external domain) pairs met the 20-connection minimum. The naive count ranking was dominated by `sync.collab-suite.example` (top 14 pairs, ~4,300 connections each); the implant pair ranked #15 by count. The interval ranking put it #1.

## Act with Knowledge

**Findings.** `WKS-0042 -> cdn-sync-07.telemetry-edge.example` (203.0.113.45) scored **80.8**, ten times the next unsanctioned pair: 3,037 connections, median interval 301 s, classic CV 0.12, robust CV 0.15, 100% of intervals in the +/-30% band, bytes_out CV 0.03 (~780 bytes per check-in). The domain is not in the inventory and first appears on 2026-09-10 at 10:21, six minutes after the H02 Excel -> cmd -> rundll32 chain on the same host. See [`results.md`](results.md).

**False-positive review.** NTP (`time.ntp-pool.example`, robust CV 0.02) and the APM agent (`telemetry.vendor-apm.example`, robust CV 0.04) are *more* regular than the implant and would score in the 90s on regularity alone. They are excluded only because they are inventoried, and that dependency is the main reason this hunt did not graduate. The Contoso update agent (hourly, +/-50% jitter, robust CV 0.40, raw score ~38) would land in the review band even without the inventory. File sync (robust CV 1.03) scores zero.

**Outcome.** True positive. Escalated as an incident; host isolated; the domain and IP went to the proxy blocklist and the TI platform. The pivot on WKS-0042 / rbaxter seeded the H02, H04 and H06 reviews.

**Detection decision: baseline documented, no detection.** A point-in-time rule cannot calculate inter-arrival statistics, and as a scheduled analytic the score depends on a maintained allowlist (NTP and APM would otherwise be the top alerts). Instead:
- `query.kql` / `query.spl` run as a **weekly scheduled hunt** with the sanctioned-beacon baseline documented above.
- The implant's IOCs were added to the blocklist (an atomic-indicator control, not a behavioural detection).
- Data gap logged: the proxy feed has no TLS client fingerprint (JA3/JA4) or SNI, which would let a future version of this hunt cluster beacons by client.

**Lessons for the next iteration.** Robust CV plus in-band fraction tolerated 20% jitter well. A beacon with 50%+ jitter would fall into the same band as the update agent, so the next iteration should add a periodogram / autocorrelation test for long-jitter beacons.
