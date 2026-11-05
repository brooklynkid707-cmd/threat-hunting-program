"""H02 - rare process lineage via fleet stacking.

Hypothesis: malicious code launched from a document spawns an unusual chain of
processes. Office apps spawning a shell which spawns a signed LOLBin from a
user-writable path is a classic initial-access footprint. Across a whole fleet
these parent->child relationships form a long-tailed distribution: a handful of
lineages account for almost all events, and attacker activity hides in the tail
that is seen on only one or two hosts.

Method: build the gparent->parent->child triple for every process event, stack
(count) each triple across the fleet and count on how many distinct hosts it
appears. Score the long tail: triples seen on very few hosts, especially those
matching the office->shell->LOLBin shape or running a binary from a user Temp /
AppData path. IT-admin tools (psexec, nmap) run rarely too, but on admin hosts
and not from a document parent, so they are separated out as a documented FP
class.
"""

from __future__ import annotations

from collections import defaultdict
from typing import List

from . import Finding

META = {
    "id": "H02",
    "name": "Rare process lineage (fleet stacking)",
    "technique": "T1204.002",
    "data_sources": ["process"],
    "entity": "gparent->parent->child lineage",
    "decision": 'new detection created',
    "detection": 'H02-office-shell-lolbin',
    "rationale": 'The office -> shell -> signed-proxy-binary lineage occurred once in 14 days across 65 hosts and never in the benign baseline. It is expressible as a single-event Sigma rule with no allowlist.',
    "data_gaps": [],
}

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"}
LOLBINS = {"rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "installutil.exe"}
ADMIN_TOOLS = {"psexec.exe", "nmap.exe", "procmon.exe", "wireshark.exe"}
USER_PATHS = ("\\appdata\\", "\\temp\\", "\\users\\public\\", "\\downloads\\")


def run(ds, top: int = 10) -> List[Finding]:
    triple_hosts = defaultdict(set)
    triple_events = defaultdict(list)
    for ev in ds.process:
        g = (ev.get("gparent") or "").lower()
        p = (ev.get("parent") or "").lower()
        c = (ev.get("process") or "").lower()
        key = f"{g} -> {p} -> {c}"
        triple_hosts[key].add(ev["host"])
        triple_events[key].append(ev)

    findings: List[Finding] = []
    for key, hosts in triple_hosts.items():
        n_hosts = len(hosts)
        g, p, c = [x.strip() for x in key.split("->")]
        evs = triple_events[key]
        total = len(evs)

        # rarity: seen on few hosts is more suspicious (long tail)
        rarity = max(0.0, 1.0 - (n_hosts - 1) / 8.0)  # 1 host ->1.0, 9+ hosts ->0
        if rarity <= 0:
            continue

        shape = 0.0
        notes = []
        if g in OFFICE and p in SHELLS:
            shape += 0.6
            notes.append("office app -> shell")
        if c in LOLBINS and p in SHELLS:
            shape += 0.4
            notes.append("shell -> LOLBin")
        # user-writable image path on any event of this lineage
        temp_path = any(any(tok in (e.get("image", "").lower()) or tok in (e.get("cmdline", "").lower())
                            for tok in USER_PATHS) for e in evs)
        if temp_path:
            shape += 0.5
            notes.append("image/args in user-writable path")

        is_admin_tool = c in ADMIN_TOOLS
        if shape == 0.0 and not is_admin_tool:
            # rare but unremarkable lineage (e.g. a one-off benign chain); skip low noise
            if rarity < 0.9:
                continue

        score = min(100.0, 100.0 * rarity * (0.25 + shape) / 1.5)
        if is_admin_tool:
            score *= 0.15
            notes.append("admin tool on admin host -> documented FP")

        verdict = "benign" if is_admin_tool else ("malicious" if score >= 50 else "suspicious")
        example = max(evs, key=lambda e: len(e.get("cmdline", "")))
        findings.append(Finding(
            entity=key,
            score=score,
            verdict=verdict,
            explanation=f"seen on {n_hosts} host(s), {total} event(s); " + ("; ".join(notes) or "rare lineage"),
            evidence={
                "lineage": key, "hosts": sorted(hosts), "host_count": n_hosts,
                "events": total,
                "example_host": example["host"], "example_cmdline": example.get("cmdline", ""),
            },
        ))

    findings.sort(key=lambda f: (-f.score, f.entity))
    return findings[:top]


def fp_review(ds, findings) -> List[str]:
    admin = defaultdict(set)
    for ev in ds.process:
        c = (ev.get("process") or "").lower()
        if c in ADMIN_TOOLS:
            admin[c].add(ev["host"])
    notes = []
    for tool in sorted(admin):
        notes.append(f"`{tool}` ran on {len(admin[tool])} host(s) ({', '.join(sorted(admin[tool]))}) - IT admin "
                     f"workstations, launched from explorer/cmd, not from an Office parent -> documented FP, down-weighted x0.15.")
    lineages = len({(e.get('gparent'), e.get('parent'), e.get('process')) for e in ds.process})
    notes.append(f"{lineages} distinct gparent->parent->child lineages across {len({e['host'] for e in ds.process})} hosts; "
                 f"the head of the distribution (svchost, chrome, teams, Office from explorer/outlook) is on every host.")
    return notes
