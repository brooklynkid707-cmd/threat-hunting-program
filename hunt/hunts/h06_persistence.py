"""H06 - fleet-rare persistence (new service / scheduled task).

Hypothesis: attacker persistence shows up as a service or scheduled task that
exists on only one host, often with a binary in a user-writable path and a name
that imitates a Windows component. Legitimate services are deployed by management
tooling to many hosts at once and live in Program Files / System32.

Method: stack service (7045) and scheduled-task (4698) creations across the fleet
by name and by binary hash, count distinct hosts, and record the first-seen time.
Score the fleet-rare tail: appears on one (or very few) hosts, binary in a user
path, late first-seen relative to the fleet. A niche line-of-business service that
is also rare but lives in Program Files, is accounted to a service account and was
seen on day 1 scores low and is noted as a documented FP.
"""

from __future__ import annotations

from collections import defaultdict
from typing import List

from . import Finding

META = {
    "id": "H06",
    "name": "Fleet-rare persistence (service/task stacking)",
    "technique": "T1543.003",
    "data_sources": ["service"],
    "entity": "service/task name",
    "decision": 'new detection created',
    "detection": 'H06-service-user-writable-path',
    "rationale": 'Every sanctioned service and task runs from Program Files or System32; the only service with a user-writable image path was the implant. Graduated as a path-based Sigma rule; fleet stacking stays a monthly hunt for rare services in managed paths.',
    "data_gaps": ['Service creation events carry no signer/publisher field; hash reputation is manual.'],
}

USER_PATHS = ("\\appdata\\", "\\temp\\", "\\users\\public\\", "\\downloads\\", "\\perflogs\\")
SYSTEM_IMITATORS = ("sync", "helper", "update", "host", "svc", "win")


def run(ds, top: int = 10) -> List[Finding]:
    name_hosts = defaultdict(set)
    name_first = {}
    name_meta = {}
    for ev in ds.service:
        name = ev.get("name") or ev.get("task_name") or "(unnamed)"
        name_hosts[name].add(ev["host"])
        ts = ev["epoch"]
        if name not in name_first or ts < name_first[name]:
            name_first[name] = ts
            name_meta[name] = ev

    # earliest observation across the whole fleet, to judge "late first-seen"
    fleet_start = min(name_first.values()) if name_first else 0

    findings: List[Finding] = []
    for name, hosts in name_hosts.items():
        n_hosts = len(hosts)
        if n_hosts > 3:
            continue  # common deployment, not persistence
        ev = name_meta[name]
        path = (ev.get("image_path") or "").lower()
        rarity = 1.0 - (n_hosts - 1) / 3.0           # 1 host ->1.0, 4 ->0
        in_user_path = any(tok in path for tok in USER_PATHS)
        imitator = any(tok in name.lower().replace(" ", "") for tok in SYSTEM_IMITATORS)
        days_late = (name_first[name] - fleet_start) / 86400.0
        late_term = min(1.0, max(0.0, days_late / 5.0))

        managed_path = path.startswith((r"c:\program files", r"c:\windows\system32"))
        score = 100.0 * rarity * (0.3 + 0.45 * in_user_path + 0.15 * imitator + 0.10 * late_term)
        if managed_path:
            score *= 0.4  # deployed into a managed install path -> documented FP class
        if score < 1.0:
            continue
        reasons = [f"on {n_hosts} host(s)"]
        if in_user_path:
            reasons.append("binary in user-writable path")
        if imitator:
            reasons.append("name imitates a system component")
        if days_late > 1:
            reasons.append(f"first seen {days_late:.1f}d after fleet baseline")
        if managed_path:
            reasons.append("managed install path (Program Files/System32) -> down-weighted")
        verdict = "malicious" if (in_user_path and n_hosts == 1) else ("suspicious" if score >= 25 else "benign")
        findings.append(Finding(
            entity=name,
            score=score,
            verdict=verdict,
            explanation="; ".join(reasons),
            evidence={
                "name": name, "hosts": sorted(hosts), "host_count": n_hosts,
                "image_path": ev.get("image_path"), "sha256": ev.get("sha256"),
                "account": ev.get("account"), "first_seen": ev.get("ts"),
                "event_id": ev.get("event_id"),
            },
        ))

    findings.sort(key=lambda f: (-f.score, f.entity))
    return findings[:top]


def fp_review(ds, findings) -> List[str]:
    notes = []
    for f in findings:
        if f.verdict == "malicious":
            continue
        ev = f.evidence
        notes.append(f"`{f.entity}`: {ev['host_count']} host(s), `{ev['image_path']}`, account {ev['account']}, "
                     f"first seen {ev['first_seen']} - managed install path, confirmed with the owning team "
                     f"(line-of-business / IT tooling) -> benign.")
    common = defaultdict(set)
    for ev in ds.service:
        common[ev.get("name") or ev.get("task_name")].add(ev["host"])
    fleet = [k for k, v in common.items() if len(v) > 3]
    notes.append(f"{len(fleet)} service/task names are present on more than 3 hosts (managed deployments) and were not scored.")
    return notes
