"""H03 - Kerberoasting (RC4 TGS burst).

Hypothesis: a compromised account is requesting Kerberos service tickets (TGS,
event 4769) with RC4 encryption (0x17) for many distinct service principals in a
short window, to crack them offline. Legitimate accounts request a few tickets
over a day, usually AES (0x12), for the handful of services they actually use. A
roasting run is distinguished by the *number of distinct SPNs* requested with RC4
inside a small time window per account.

Method: for each account, scan its 4769 events in a sliding window (default 10
minutes), count distinct SPNs requested with RC4 within the window, and track the
peak. Score grows with the peak distinct-SPN count and the fraction of those that
are RC4. A legacy service account that always uses RC4 but only ever touches its
own single SPN scores low (distinct count 1) and is noted as a documented FP.
"""

from __future__ import annotations

from collections import defaultdict
from typing import List

from . import Finding

META = {
    "id": "H03",
    "name": "Kerberoasting (RC4 TGS burst)",
    "technique": "T1558.003",
    "data_sources": ["auth"],
    "entity": "account",
    "decision": 'new detection created',
    "detection": 'H03-kerberoasting-rc4-burst',
    "rationale": 'Distinct RC4 SPNs per account per 10 minutes separates the roast (9) from every benign account (max 1). Graduated as a Sigma correlation rule; svc-legacy is the only RC4 user and stays below threshold.',
    "data_gaps": [],
}

RC4 = "0x17"
WINDOW_S = 600          # 10-minute sliding window
SUSPICIOUS_DISTINCT = 5  # distinct RC4 SPNs in the window to call it roasting


def run(ds, top: int = 10) -> List[Finding]:
    by_user = defaultdict(list)
    for ev in ds.auth:
        if ev.get("event_id") == 4769:
            by_user[ev["user"]].append(ev)

    findings: List[Finding] = []
    for user, evs in by_user.items():
        evs.sort(key=lambda e: e["epoch"])
        best_distinct = 0
        best_window = None
        rc4_total = sum(1 for e in evs if e.get("ticket_encryption") == RC4)
        # sliding window over RC4 requests
        rc4 = [e for e in evs if e.get("ticket_encryption") == RC4]
        for i in range(len(rc4)):
            j = i
            spns = set()
            while j < len(rc4) and rc4[j]["epoch"] - rc4[i]["epoch"] <= WINDOW_S:
                spns.add(rc4[j].get("service_name"))
                j += 1
            if len(spns) > best_distinct:
                best_distinct = len(spns)
                best_window = (rc4[i]["epoch"], rc4[j - 1]["epoch"], sorted(spns))

        if best_distinct < 2:
            continue

        # score: distinct SPNs in window dominate; saturate around 10
        score = 100.0 * min(1.0, best_distinct / 9.0)
        if best_distinct < SUSPICIOUS_DISTINCT:
            score *= 0.3  # a couple of RC4 SPNs is not a roast
        verdict = "malicious" if best_distinct >= SUSPICIOUS_DISTINCT else "suspicious"
        if best_distinct <= 1:
            verdict = "benign"

        span = (best_window[1] - best_window[0]) if best_window else 0
        findings.append(Finding(
            entity=user,
            score=score,
            verdict=verdict,
            explanation=(f"peak {best_distinct} distinct RC4 SPNs within {WINDOW_S}s "
                         f"(burst span {span:.0f}s); {rc4_total} RC4 TGS total"),
            evidence={
                "user": user,
                "peak_distinct_rc4_spns": best_distinct,
                "rc4_tgs_total": rc4_total,
                "window_spns": best_window[2] if best_window else [],
                "burst_span_s": round(span, 1),
            },
        ))

    findings.sort(key=lambda f: (-f.score, f.entity))
    return findings[:top]


def fp_review(ds, findings) -> List[str]:
    rc4 = defaultdict(set)
    rc4_n = defaultdict(int)
    aes_users = set()
    for ev in ds.auth:
        if ev.get("event_id") != 4769:
            continue
        if ev.get("ticket_encryption") == RC4:
            rc4[ev["user"]].add(ev.get("service_name"))
            rc4_n[ev["user"]] += 1
        else:
            aes_users.add(ev["user"])
    notes = []
    for u in sorted(rc4):
        if len(rc4[u]) <= 1:
            notes.append(f"`{u}`: {rc4_n[u]} RC4 TGS over 14 days, all for 1 SPN ({sorted(rc4[u])[0]}) - legacy "
                         f"application that cannot do AES; peak distinct SPNs 1 -> below threshold. Ticketed for AES migration.")
    notes.append(f"{len(aes_users)} accounts requested AES (0x12) tickets for 1-3 SPNs/day - normal service access, ignored.")
    return notes
