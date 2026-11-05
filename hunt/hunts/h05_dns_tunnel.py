"""H05 - DNS tunneling (high-entropy, high-cardinality subdomains).

Hypothesis: data is being exfiltrated or a C2 channel is being run over DNS by
encoding bytes into subdomain labels under a single registered domain. The tell
is a domain whose child labels are long, high-entropy (look random) and
*numerous* - hundreds of unique subdomains, often with TXT queries. Content
delivery networks also generate many random-looking subdomains, but their labels
are short, so label length and per-query entropy separate them.

Method: group DNS queries by registered (second-level) domain. For each domain
compute the count of unique subdomain labels, the mean label length, the mean
Shannon entropy of the labels, and the query volume. Score rewards long + high
entropy + high unique cardinality. Known CDNs (short labels) fall out naturally
because of the length and entropy terms; they are also listed as a documented FP.
"""

from __future__ import annotations

from collections import defaultdict
from typing import List

from .. import inventory, stats
from . import Finding

META = {
    "id": "H05",
    "name": "DNS tunneling (subdomain entropy/cardinality)",
    "technique": "T1048.003",
    "data_sources": ["dns"],
    "entity": "registered domain",
    "decision": 'data gap found',
    "detection": None,
    "rationale": 'The tunnel was found, but resolver logs record query name and type only: no response size or TXT answer data. The strongest tunneling signal (bytes carried per domain) cannot be measured, and an always-on rule would rest on label length alone. Gap logged as backlog H11; hunt stays weekly.',
    "data_gaps": ['DNS resolver logs lack response size / answer payload for TXT queries (backlog H11).'],
}

KNOWN_CDNS = set(inventory.KNOWN_CDNS)


def _registered(qname: str) -> str:
    parts = qname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return qname


def _subdomain(qname: str, registered: str) -> str:
    if qname.endswith(registered):
        return qname[: -len(registered)].rstrip(".")
    return qname


def run(ds, top: int = 10) -> List[Finding]:
    by_domain = defaultdict(list)
    txt_count = defaultdict(int)
    for ev in ds.dns:
        qn = ev.get("qname", "")
        reg = _registered(qn)
        sub = _subdomain(qn, reg)
        if sub:
            by_domain[reg].append(sub)
            if ev.get("qtype") == "TXT":
                txt_count[reg] += 1

    findings: List[Finding] = []
    for reg, subs in by_domain.items():
        uniq = set(subs)
        n_unique = len(uniq)
        if n_unique < 10:
            continue
        # use the first label of each subdomain for length/entropy
        first_labels = [s.split(".")[0] for s in uniq]
        mean_len = stats.mean([len(x) for x in first_labels])
        mean_ent = stats.mean([stats.shannon_entropy(x) for x in first_labels])
        volume = len(subs)

        is_cdn = reg in KNOWN_CDNS

        # length term: tunnel labels are long (>=25). Map 10..40 -> 0..1
        len_term = max(0.0, min(1.0, (mean_len - 10) / 30.0))
        # entropy term: >3.5 bits/char is random-looking. Map 2.5..4.5 -> 0..1
        ent_term = max(0.0, min(1.0, (mean_ent - 2.5) / 2.0))
        # cardinality term: many unique labels. Map 10..300 -> 0..1
        card_term = max(0.0, min(1.0, (n_unique - 10) / 290.0))
        txt_bonus = 0.1 if txt_count.get(reg, 0) > 0 else 0.0

        score = 100.0 * (0.4 * len_term + 0.3 * ent_term + 0.3 * card_term + txt_bonus)
        if is_cdn:
            score *= 0.1
        if score < 1.0:
            continue
        verdict = "benign" if is_cdn else ("malicious" if score >= 45 else "suspicious")
        findings.append(Finding(
            entity=reg,
            score=score,
            verdict=verdict,
            explanation=(f"{n_unique} unique subdomains, mean label len {mean_len:.1f}, "
                         f"mean entropy {mean_ent:.2f} bits/char, {volume} queries"
                         + (", known CDN -> suppressed" if is_cdn else "")),
            evidence={
                "registered_domain": reg,
                "unique_subdomains": n_unique,
                "mean_label_length": round(mean_len, 2),
                "mean_entropy_bits": round(mean_ent, 3),
                "query_volume": volume,
                "txt_queries": txt_count.get(reg, 0),
                "is_known_cdn": is_cdn,
            },
        ))

    findings.sort(key=lambda f: (-f.score, f.entity))
    return findings[:top]


def fp_review(ds, findings) -> List[str]:
    notes = []
    for f in findings:
        ev = f.evidence
        if ev.get("is_known_cdn"):
            notes.append(f"`{f.entity}`: {ev['unique_subdomains']} unique subdomains (high cardinality) but mean label "
                         f"length {ev['mean_label_length']} and entropy {ev['mean_entropy_bits']} bits/char - CDN edge "
                         f"hostnames, known CDN -> suppressed x0.1.")
    notes.append("Every other registered domain had fewer than 10 unique subdomains and was not scored.")
    return notes
