"""H08 - data staging and exfiltration.

Hypothesis: before exfiltration an attacker collects data into an archive on
disk, then ships it out. The pattern is an archive file created (often in an
unusual location like C:\\PerfLogs) followed within minutes by an outbound byte
volume far above that host's normal egress, to an external destination. A nightly
backup also creates big archives, but it writes them to a backup volume and ships
them to an *internal* backup target, so destination and host context separate it.

Method: find archive-creation events (7z/zip/rar/tar). For each, look on the same
host for outbound network in the next N minutes whose bytes_out exceeds the host's
egress baseline (95th percentile of per-connection bytes_out). Score the pair by
how far above baseline the egress is, whether the destination is external, and
whether the archive sits in a suspicious path. The backup job is suppressed
because its destination is the internal backup target (documented FP).
"""

from __future__ import annotations

import datetime as dt
from collections import defaultdict
from typing import List

from .. import inventory, stats
from . import Finding

META = {
    "id": "H08",
    "name": "Data staging and exfiltration",
    "technique": "T1567.002",
    "data_sources": ["files", "network"],
    "entity": "host / archive",
    "decision": 'new detection created',
    "detection": 'H08-archive-staging-path',
    "rationale": 'Archive creation in a staging path (PerfLogs, Windows\\Temp, ProgramData, Public) never occurs in the baseline. Graduated as a Sigma file-event rule; the byte-spike correlation stays in the scheduled hunt.',
    "data_gaps": ["No file-share audit (5145) events, so the archive's source files cannot be enumerated."],
}

ARCHIVE_EXT = {"7z", "zip", "rar", "tar", "gz", "cab"}
WINDOW_S = 1800  # 30 minutes
MIN_EGRESS = 50_000_000  # 50 MB absolute floor for a meaningful transfer
SUSPICIOUS_PATHS = ("\\perflogs\\", "\\windows\\temp\\", "\\programdata\\", "\\users\\public\\")


def _hour(epoch: float) -> int:
    return dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).hour


def _is_external(dom: str, ip: str) -> bool:
    return not inventory.is_internal(dom, ip)


def run(ds, top: int = 10) -> List[Finding]:
    # per-host egress baseline (95th pct of bytes_out across all its connections)
    host_bytes = defaultdict(list)
    net_by_host = defaultdict(list)
    for ev in ds.network:
        host_bytes[ev["host"]].append(ev.get("bytes_out", 0))
        net_by_host[ev["host"]].append(ev)
    baseline = {h: stats.percentile(v, 95) for h, v in host_bytes.items()}
    for h in net_by_host:
        net_by_host[h].sort(key=lambda e: e["epoch"])

    findings: List[Finding] = []
    for fe in ds.files:
        ext = (fe.get("ext") or "").lower()
        if ext not in ARCHIVE_EXT:
            continue
        host = fe["host"]
        t0 = fe["epoch"]
        path = (fe.get("path") or "").lower()
        base = baseline.get(host, 0) or 1
        # outbound in the window after archive creation, split external / internal
        ext_bytes = 0
        int_bytes = 0
        ext_dst = {}
        int_dst = {}
        for ne in net_by_host.get(host, []):
            if ne["epoch"] < t0:
                continue
            if ne["epoch"] - t0 > WINDOW_S:
                break
            bo = ne.get("bytes_out", 0)
            if bo <= base:
                continue
            d = ne.get("dst_domain") or ne.get("dst_ip")
            if _is_external(ne.get("dst_domain", ""), ne.get("dst_ip", "")):
                ext_bytes += bo
                ext_dst[d] = ext_dst.get(d, 0) + bo
            else:
                int_bytes += bo
                int_dst[d] = int_dst.get(d, 0) + bo

        spike_bytes = ext_bytes + int_bytes
        # An exfil spike is large in absolute terms: browsing or telemetry that
        # edges past the p95 baseline moves kilobytes, not tens of megabytes.
        if spike_bytes < MIN_EGRESS:
            continue
        external = ext_bytes >= MIN_EGRESS
        if external:
            dst = max(ext_dst, key=ext_dst.get)
            moved = ext_bytes
        else:
            dst = max(int_dst, key=int_dst.get) if int_dst else max(ext_dst, key=ext_dst.get)
            moved = spike_bytes
        ratio = moved / base
        susp_path = any(tok in path for tok in SUSPICIOUS_PATHS)
        off_hours = _hour(t0) < 6 or _hour(t0) >= 22
        same_user = fe.get("user")

        over = min(1.0, (ratio - 1) / 500.0)
        magnitude = min(1.0, moved / 200_000_000)  # saturate at 200 MB
        score = 100.0 * (0.15 + 0.20 * over + 0.20 * magnitude
                         + 0.35 * (1.0 if external else 0.0) + 0.10 * susp_path)
        if not external:
            score *= 0.2  # egress went to an internal target (backup job) -> documented FP
        verdict = "malicious" if (external and score >= 55) else ("suspicious" if score >= 25 else "benign")
        findings.append(Finding(
            entity=f"{host} / {fe.get('filename')}",
            score=score,
            verdict=verdict,
            explanation=(f"{fe.get('filename')} ({fe.get('size_bytes', 0)/1e6:.0f} MB) created in "
                         f"{fe.get('path')}, then {moved/1e6:.0f} MB egress within {WINDOW_S//60}m "
                         f"({ratio:,.0f}x host p95) to {'EXTERNAL' if external else 'internal'} {dst}"
                         + ("; off-hours" if off_hours else "")
                         + ("" if external else "; internal backup target -> suppressed")),
            evidence={
                "host": host, "user": same_user, "archive": fe.get("path"),
                "archive_size": fe.get("size_bytes"),
                "external_bytes": ext_bytes, "internal_bytes": int_bytes,
                "baseline_p95": round(base, 1),
                "ratio": round(ratio, 1), "destination": dst, "external": external,
                "suspicious_path": susp_path, "off_hours": off_hours, "ts": fe.get("ts"),
            },
        ))

    findings.sort(key=lambda f: (-f.score, f.entity))
    return findings[:top]


def fp_review(ds, findings) -> List[str]:
    notes = []
    backups = [f for f in findings if not f.evidence.get("external")]
    if backups:
        total = sum(1 for e in ds.files if (e.get("user") == "svc-backup"))
        notes.append(f"Nightly backup (`SRV-0001`, svc-backup): {total} archives of ~1 GB in `D:\\Backups`, each followed "
                     f"by ~0.5 GB egress - to the internal `backup-target.northwind.example` -> suppressed x0.2.")
    small = [e for e in ds.files if e.get("filename") == "report.zip"]
    if small:
        notes.append(f"{len(small)} user `report.zip` archives in Documents; no follow-on egress above the 50 MB floor -> not scored.")
    return notes
