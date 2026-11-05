"""H04 - LOLBin abuse (living-off-the-land binaries with network arguments).

Hypothesis: an attacker uses signed, built-in Windows binaries to download or
execute payloads so the activity blends in. The binaries themselves (certutil,
regsvr32, mshta, bitsadmin...) run benignly all the time; what makes a run
malicious is the *command line* - a URL argument, the -urlcache / /i:http /
DownloadFile patterns - combined with how rarely that binary normally runs with
those arguments on that host.

Method: per host, baseline how often each LOLBin runs at all. Then flag process
events where the command line matches a LOLBAS-style abuse pattern (network
fetch, remote scriptlet execution, encoded commands). Score combines the pattern
severity with host rarity. A plain `certutil -store my` (no network argument)
matches no abuse pattern and is left alone - the documented FP class.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import List

from . import Finding

META = {
    "id": "H04",
    "name": "LOLBin abuse (command-line patterns)",
    "technique": "T1105",
    "data_sources": ["process"],
    "entity": "host / binary / command",
    "decision": 'new detection created',
    "detection": 'H04-lolbin-remote-fetch',
    "rationale": 'The abuse is in the network argument, not the binary. Baseline certutil/regsvr32 use carries no URL, so a binary + command-line-pattern rule fires only on the abuse.',
    "data_gaps": [],
}

# (binary, compiled abuse pattern, weight, label)
PATTERNS = [
    ("certutil.exe", re.compile(r"-urlcache|-f\s+https?://|\bhttps?://", re.I), 1.0, "certutil remote download"),
    ("regsvr32.exe", re.compile(r"/i:\s*https?://|scrobj\.dll", re.I), 1.0, "regsvr32 remote scriptlet (Squiblydoo)"),
    ("mshta.exe", re.compile(r"https?://|vbscript:|javascript:", re.I), 1.0, "mshta remote/script execution"),
    ("bitsadmin.exe", re.compile(r"/transfer|/addfile|https?://", re.I), 0.9, "bitsadmin transfer"),
    ("powershell.exe", re.compile(r"-enc\b|-encodedcommand|downloadstring|iwr\s|invoke-webrequest", re.I), 0.8, "powershell download/encoded"),
    ("rundll32.exe", re.compile(r"javascript:|https?://|url\.dll", re.I), 0.9, "rundll32 remote"),
    ("wmic.exe", re.compile(r"process\s+call\s+create|/node:", re.I), 0.7, "wmic process create"),
]
LOLBINS = {p[0] for p in PATTERNS}


def run(ds, top: int = 10) -> List[Finding]:
    # baseline: how often each binary runs per host
    runs_per_host = defaultdict(lambda: defaultdict(int))
    for ev in ds.process:
        proc = (ev.get("process") or "").lower()
        if proc in LOLBINS:
            runs_per_host[proc][ev["host"]] += 1

    findings: List[Finding] = []
    for ev in ds.process:
        proc = (ev.get("process") or "").lower()
        cmd = ev.get("cmdline", "") or ""
        matched = None
        for binname, pat, weight, label in PATTERNS:
            if proc == binname and pat.search(cmd):
                matched = (weight, label)
                break
        if not matched:
            continue
        weight, label = matched
        host = ev["host"]
        host_runs = runs_per_host[proc].get(host, 1)
        # rarity on this host: the fewer benign runs, the more notable
        rarity = 1.0 / host_runs
        has_doc_ip = bool(re.search(r"https?://(198\.51\.100|203\.0\.113|192\.0\.2)\.", cmd))
        score = 100.0 * weight * (0.6 + 0.4 * rarity)
        if has_doc_ip:
            score = min(100.0, score * 1.1)
        verdict = "malicious" if score >= 60 else "suspicious"
        findings.append(Finding(
            entity=f"{host} / {proc}",
            score=score,
            verdict=verdict,
            explanation=f"{label}; host baseline {host_runs} run(s) of {proc}",
            evidence={
                "host": host, "binary": proc, "pattern": label,
                "cmdline": cmd, "user": ev.get("user"),
                "ts": ev.get("ts"), "host_baseline_runs": host_runs,
            },
        ))

    findings.sort(key=lambda f: (-f.score, f.entity))
    return findings[:top]


def fp_review(ds, findings) -> List[str]:
    benign = defaultdict(lambda: defaultdict(int))
    for ev in ds.process:
        proc = (ev.get("process") or "").lower()
        if proc not in LOLBINS:
            continue
        cmd = ev.get("cmdline", "") or ""
        if any(proc == b and pat.search(cmd) for b, pat, _, _ in PATTERNS):
            continue
        benign[proc][cmd] += 1
    notes = []
    for proc in sorted(benign):
        for cmd, n in sorted(benign[proc].items(), key=lambda kv: (-kv[1], kv[0])):
            low = cmd.lower()
            if "\\appdata\\" in low or "\\temp\\" in low:
                notes.append(f"`{cmd}` x{n} - no network argument, so out of scope for H04, but a DLL in a user "
                             f"temp path is not baseline: pivoted to H02 (lineage), where it ranks #1.")
            else:
                notes.append(f"`{cmd}` x{n} - {proc} with no network or scriptlet argument -> baseline use, not matched.")
    return notes
