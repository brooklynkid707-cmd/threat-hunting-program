"""H07 - anomalous logon behaviour (per-account baseline).

Hypothesis: a compromised account is used in a way it never normally is - a
service account that only ever does non-interactive (service/network) logons
suddenly logs on interactively, or at an hour it never works. The signal is
"never before seen for this account", which a per-account baseline of logon types
and active hours captures directly and a fleet-wide rule would miss.

Method: for each account build a baseline over the whole period: the distribution
of logon types and of active hours. An account is anomalous when an interactive
logon (type 2/10/11) is a *tiny fraction* of an otherwise non-interactive history
- i.e. the account is fundamentally a service/batch identity that did one
interactive logon - and more so when that logon is off-hours. Normal users, whose
interactive logons are a large share of their history, keep a low score because
interactive logons are already their baseline, not a novelty.
"""

from __future__ import annotations

import datetime as dt
from collections import defaultdict
from typing import List

from .. import stats
from . import Finding

META = {
    "id": "H07",
    "name": "Anomalous logon behaviour (per-account baseline)",
    "technique": "T1078.002",
    "data_sources": ["auth"],
    "entity": "account",
    "decision": 'new detection created',
    "detection": 'H07-service-account-interactive-logon',
    "rationale": "No service account had an interactive logon in the baseline. 'svc-* with logon type 2/10/11' is a zero-baseline condition, so it graduates as a simple rule; the per-account hour baseline remains a hunt.",
    "data_gaps": [],
}

INTERACTIVE = {2, 10, 11}        # interactive, remote-interactive, cached interactive
NONINTERACTIVE = {3, 4, 5}       # network, batch, service
RARE_FRACTION = 0.10             # interactive <=10% of history = "not this account's norm"


def _hour(epoch: float) -> int:
    return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).hour


def run(ds, top: int = 10) -> List[Finding]:
    logons = defaultdict(list)
    for ev in ds.auth:
        if ev.get("event_id") == 4624:
            logons[ev["user"]].append(ev)

    findings: List[Finding] = []
    for user, evs in logons.items():
        evs.sort(key=lambda e: e["epoch"])
        total = len(evs)
        interactive_evs = [e for e in evs if e.get("logon_type") in INTERACTIVE]
        noninteractive_evs = [e for e in evs if e.get("logon_type") in NONINTERACTIVE]
        n_int = len(interactive_evs)
        if n_int == 0:
            continue
        int_fraction = n_int / total

        # Only interesting when interactive is a rare novelty for a predominantly
        # non-interactive account. This excludes ordinary users outright.
        if not noninteractive_evs:
            continue
        if int_fraction > RARE_FRACTION:
            continue

        # pick the strongest anomalous interactive logon
        hours_all = [_hour(e["epoch"]) for e in noninteractive_evs]
        best = None
        best_s = 0.0
        for e in interactive_evs:
            hr = _hour(e["epoch"])
            off_hours = hr < 6 or hr >= 22
            hz = abs(stats.mad_zscore(hr, hours_all)) if len(hours_all) >= 4 else 0.0
            s = 0.7                       # novel interactive type for a service identity
            if off_hours:
                s += 0.25
            if hz >= 3.5:
                s += 0.05
            if s > best_s:
                best_s = s
                best = {"ts": e.get("ts"), "logon_type": e.get("logon_type"),
                        "hour": hr, "src_ip": e.get("src_ip"), "host": e.get("host"),
                        "off_hours": off_hours, "hour_mad_z": round(hz, 2)}

        score = 100.0 * min(1.0, best_s)
        if user.startswith("svc-"):
            score = min(100.0, score * 1.05)
        verdict = "malicious" if score >= 60 else "suspicious"
        findings.append(Finding(
            entity=user,
            score=score,
            verdict=verdict,
            explanation=(f"interactive logon (type {best['logon_type']}) is {int_fraction:.0%} of this "
                         f"account's history at {best['hour']:02d}:00"
                         + (" (off-hours)" if best["off_hours"] else "")),
            evidence={
                "user": user, "interactive_fraction": round(int_fraction, 4),
                "total_logons": total, "interactive_logons": n_int,
                "baseline_logon_types": sorted({e.get("logon_type") for e in evs if e.get("logon_type") is not None}),
                "anomaly": best,
            },
        ))

    findings.sort(key=lambda f: (-f.score, f.entity))
    return findings[:top]


def fp_review(ds, findings) -> List[str]:
    per = defaultdict(list)
    for ev in ds.auth:
        if ev.get("event_id") == 4624:
            per[ev["user"]].append(ev)
    notes = []
    late = []
    for u, evs in per.items():
        ints = [e for e in evs if e.get("logon_type") in INTERACTIVE]
        off = [e for e in ints if _hour(e["epoch"]) >= 22 or _hour(e["epoch"]) < 6]
        if off and not u.startswith("svc-"):
            late.append((u, len(off), len(ints) / len(evs)))
    for u, n, frac in sorted(late):
        notes.append(f"`{u}`: {n} off-hours interactive logon(s) on own workstation, but interactive logons are "
                     f"{frac:.0%} of the account's history -> within baseline, not a novelty.")
    for sa in sorted(u for u in per if u.startswith("svc-")):
        types = sorted({e.get("logon_type") for e in per[sa]})
        if not set(types) & INTERACTIVE:
            off = sum(1 for e in per[sa] if _hour(e["epoch"]) < 6)
            extra = f", {off} of them between 00:00-06:00 (scheduled jobs)" if off else ""
            notes.append(f"`{sa}`: {len(per[sa])} logons, types {types}{extra} - non-interactive only -> consistent with baseline.")
    return notes
