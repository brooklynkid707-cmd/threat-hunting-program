# H05 - DNS tunneling via high-entropy subdomains

PEAK type: **hypothesis-driven** | ATT&CK: **T1048.003** Exfiltration Over Unencrypted Non-C2 Protocol, **T1071.004** Application Layer Protocol: DNS | Status: **closed - data gap found**

## Prepare

**Hypothesis.** A host is moving data out, or receiving tasking, by encoding it into DNS query labels under an attacker-controlled domain. The internal resolvers forward any name, and a red-team finding showed DNS egress is not restricted at the resolver. If so, one registered domain will have many unique child labels that are long and close to random (high Shannon entropy), often with TXT queries.

**Why this hypothesis now.** Red-team finding plus ATT&CK. Resolver logs are collected but only partially (see data gap). Backlog priority 9.6.

**Data sources.** Internal resolver query logs (`dns`): host, query name, query type. **Not collected:** response size, answer payload.

**Assumptions.**
- Every endpoint uses the internal resolvers. A host using DoH or an external resolver directly would be invisible here.
- Registered domain = last two labels. That is correct for `.example` names; production uses the Public Suffix List.
- CDNs produce many unique, random-looking subdomains, but their labels are short.

**Scope.** All resolver queries, 14 days (12.8k queries, 17 registered domains); domains with at least 10 unique subdomains are scored.

## Execute

**Method.** `hunt/hunts/h05_dns_tunnel.py`; production `query.kql` / `query.spl`.

1. Split each query into registered domain + subdomain.
2. Per registered domain: number of unique subdomains (cardinality), mean leftmost-label length, mean Shannon entropy of the leftmost label (bits/char), total and TXT query volume.
3. Score = 0.4 x length term (10 -> 40 chars) + 0.3 x entropy term (2.5 -> 4.5 bits) + 0.3 x cardinality term (10 -> 300) + 0.1 if any TXT queries. Known CDNs x0.1.

**Execution notes.** Three registered domains had 10+ unique subdomains: two CDNs and one other.

## Act with Knowledge

**Findings.** `dataxfil-svc.example` (zone `sync.dataxfil-svc.example`) scored **97.4**: 239 unique subdomains out of 239 queries (no label ever repeated), mean label length 36.8, mean entropy **4.37 bits/char** (base36-like), all TXT, all from **WKS-0042** between 2026-09-12 and 2026-09-15. See [`results.md`](results.md).

**False-positive review.** `akamai-cdn.example` (1,663 unique subdomains) and `cloudfront-dist.example` (1,702) have *higher* cardinality than the tunnel, so cardinality alone would rank them first. Their labels average 6 characters at ~2.25 bits/char of hex, so length and entropy separate them even before the CDN suppression.

**Outcome.** True positive, on the beachhead host already under investigation. The domain was sinkholed at the resolver.

**Detection decision: data gap found.** The hunt found the tunnel, but it cannot answer the question the business asks: **how much data left?** Resolver logs carry query name and type only, with no response size or TXT answer payload, so bytes per domain cannot be calculated. An always-on rule would rest on label length and entropy alone, which is fragile against tunnels that use shorter labels across more queries. Actions:
- Gap logged as backlog **H11** (DNS response size anomalies), blocked until resolver analytic logging (or Zeek `dns.log` with answers) is enabled.
- This hunt stays on a **weekly cadence** using `query.kql` / `query.spl`.
- No Sigma rule was graduated. A single-event "long TXT label" rule was considered and rejected: it says nothing about cardinality, and it would page on security products that legitimately put data in TXT lookups.
