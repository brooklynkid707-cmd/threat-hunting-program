"""H01 - C2 beaconing via inter-arrival statistics.

Hypothesis: a compromised host is beaconing to C2 on a roughly fixed interval
with jitter, at low data volume, to a destination that is not sanctioned software.

Why simple frequency fails: ranking (host, domain) pairs by connection count puts
chatty, event-driven software (the file-sync client makes thousands of connections
a day) far above a low-and-slow implant, and a "more than N connections per hour"
threshold fires on every sync client in the fleet. Count measures *how much*;
beaconing is about *how regular*. `naive_frequency_ranking()` is kept in this
module so results.md can show the contrast with real numbers.

Method (jitter-tolerant): for each (host, external domain) pair with enough
connections, compute the inter-arrival deltas and
  * median interval and classic coefficient of variation (CV = stdev/mean),
  * robust CV = 1.4826 * MAD / median, which tolerates the occasional missed
    check-in or sleep gap that inflates the classic CV,
  * in-band fraction: share of deltas within +/-30% of the median, i.e. how much
    of the traffic sits inside a jitter band (a 20%-jitter beacon is ~100%),
  * bytes_out CV (implants send near-constant-size check-ins).
Regularity, in-band fraction and payload stability are combined into a 0-100
score; sanctioned destinations from the software inventory are suppressed (x0.05)
with the reason recorded, so the analyst can still see and review them.
"""

from __future__ import annotations

from collections import defaultdict
from typing import List, Tuple

from .. import inventory, stats
from . import Finding

META = {
    "id": "H01",
    "name": "C2 beaconing (inter-arrival statistics)",
    "technique": "T1071.001",
    "data_sources": ["network"],
    "entity": "host -> external domain",
    "decision": 'baseline documented, no detection',
    "detection": None,
    "rationale": 'Inter-arrival scoring needs days of history plus the sanctioned-software inventory. As a point-in-time rule it would either fire on NTP and APM telemetry (raw regularity scores in the 90s) or rest entirely on an allowlist. Kept as a weekly scheduled hunt (query.kql / query.spl) with the sanctioned-beacon baseline documented; the implant domain and IP went to the blocklist as IOCs.',
    "data_gaps": ['No TLS JA3/JA4 or SNI fields in the proxy feed; client fingerprinting would cut review time.'],
}

MIN_CONNECTIONS = 20
JITTER_BAND = 0.30


def _pairs(ds):
    groups = defaultdict(list)
    for ev in ds.network:
        dom = ev.get("dst_domain", "")
        if not dom or inventory.is_internal(dom, ev.get("dst_ip", "")):
            continue  # internal corporate traffic is out of scope for external C2
        groups[(ev["host"], dom)].append((ev["epoch"], ev.get("bytes_out", 0)))
    return groups


def naive_frequency_ranking(ds, top: int = 20) -> List[Tuple[str, int]]:
    """The approach H01 replaces: rank pairs by raw connection count."""
    counts = [(f"{h} -> {d}", len(v)) for (h, d), v in _pairs(ds).items()]
    counts.sort(key=lambda kv: (-kv[1], kv[0]))
    return counts[:top]


def pair_stats(epochs: List[float], bytes_out: List[int]) -> dict:
    epochs = sorted(epochs)
    deltas = [epochs[i + 1] - epochs[i] for i in range(len(epochs) - 1)]
    med = stats.median(deltas)
    robust_cv = (1.4826 * stats.mad(deltas) / med) if med > 0 else float("inf")
    in_band = (sum(1 for d in deltas if abs(d - med) <= JITTER_BAND * med) / len(deltas)) if deltas else 0.0
    return {
        "connections": len(epochs),
        "median_interval_s": med,
        "interval_cv": stats.coefficient_of_variation(deltas),
        "robust_cv": robust_cv,
        "in_band_fraction": in_band,
        "bytes_out_cv": stats.coefficient_of_variation(bytes_out),
        "mean_bytes_out": stats.mean(bytes_out),
    }


def beacon_score(st: dict) -> float:
    """0-100 regularity score from pair statistics (sanction-agnostic)."""
    regularity = max(0.0, 1.0 - st["robust_cv"] / 0.8)          # robust CV 0 -> 1, >=0.8 -> 0
    payload = max(0.0, 1.0 - min(1.0, st["bytes_out_cv"]))
    volume = min(1.0, st["connections"] / 200.0)
    band = 1.0 if 30 <= st["median_interval_s"] <= 7200 else 0.3
    return 100.0 * regularity * (0.40 * st["in_band_fraction"] + 0.25 * payload
                                 + 0.20 * volume + 0.15) * band


def run(ds, top: int = 10) -> List[Finding]:
    findings: List[Finding] = []
    for (host, dom), pts in _pairs(ds).items():
        if len(pts) < MIN_CONNECTIONS:
            continue
        st = pair_stats([p[0] for p in pts], [p[1] for p in pts])
        raw = beacon_score(st)
        inv = inventory.sanctioned(dom)
        score = raw * (0.05 if inv else 1.0)
        if score < 1.0:
            continue
        reasons = [
            f"{st['connections']} conns, median {st['median_interval_s']:.0f}s, "
            f"CV {st['interval_cv']:.2f}, robust CV {st['robust_cv']:.2f}, "
            f"{st['in_band_fraction']:.0%} of intervals in +/-30% band, bytes_out CV {st['bytes_out_cv']:.2f}"
        ]
        if inv:
            reasons.append(f"sanctioned: {inv[0]} ({inv[1]}) -> suppressed")
        verdict = "benign" if inv else ("malicious" if score >= 50 else ("suspicious" if score >= 20 else "benign"))
        findings.append(Finding(
            entity=f"{host} -> {dom}",
            score=score,
            verdict=verdict,
            explanation="; ".join(reasons),
            evidence={
                "host": host, "dst_domain": dom,
                "connections": st["connections"],
                "median_interval_s": round(st["median_interval_s"], 1),
                "interval_cv": round(st["interval_cv"], 3),
                "robust_cv": round(st["robust_cv"], 3),
                "in_band_fraction": round(st["in_band_fraction"], 3),
                "bytes_out_cv": round(st["bytes_out_cv"], 3),
                "mean_bytes_out": round(st["mean_bytes_out"], 1),
                "raw_score": round(raw, 2),
                "sanctioned": inv[0] if inv else None,
            },
        ))
    findings.sort(key=lambda f: (-f.score, f.entity))
    return findings[:top]


def lookalike_profiles(ds) -> List[dict]:
    """Fleet-level profile of each sanctioned beacon-like destination (for results.md)."""
    out = []
    pairs = _pairs(ds)
    for dom, inv in inventory.SOFTWARE_INVENTORY.items():
        rows = [(h, v) for (h, d), v in pairs.items() if d == dom and len(v) >= MIN_CONNECTIONS]
        if not rows:
            continue
        sts = [pair_stats([p[0] for p in v], [p[1] for p in v]) for _, v in rows]
        out.append({
            "domain": dom, "product": inv[0], "hosts": len(rows),
            "median_conns": stats.median([s["connections"] for s in sts]),
            "median_interval_s": stats.median([s["median_interval_s"] for s in sts]),
            "interval_cv": stats.median([s["interval_cv"] for s in sts]),
            "robust_cv": stats.median([s["robust_cv"] for s in sts]),
            "in_band_fraction": stats.median([s["in_band_fraction"] for s in sts]),
            "bytes_out_cv": stats.median([s["bytes_out_cv"] for s in sts]),
            "raw_score": stats.median([beacon_score(s) for s in sts]),
        })
    return out


def fp_review(ds, findings) -> List[str]:
    notes = []
    for p in lookalike_profiles(ds):
        why = ("high interval CV / wide jitter" if p["robust_cv"] > 0.3
               else "metronome-regular, would score as a beacon")
        notes.append(
            f"`{p['domain']}` ({p['product']}, {p['hosts']} hosts): median {p['median_conns']:.0f} conns, "
            f"interval {p['median_interval_s']:.0f}s, CV {p['interval_cv']:.2f}, robust CV {p['robust_cv']:.2f}, "
            f"{p['in_band_fraction']:.0%} in band, raw score {p['raw_score']:.1f} ({why}) - "
            f"excluded: domain is in the software inventory.")
    naive = naive_frequency_ranking(ds, top=10000)
    implant_rank = next((i for i, (e, _) in enumerate(naive, 1) if e == (findings[0].entity if findings else "")), None)
    if naive:
        notes.append(
            f"Naive frequency ranking (connection count) puts `{naive[0][0]}` first with {naive[0][1]} "
            f"connections; the top-scored pair ranks #{implant_rank} of {len(naive)} by count. "
            f"Counting finds chatty software, not beacons.")
    return notes
