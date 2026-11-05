"""Scoring a hunt against ground truth.

The hunts never read ground_truth.json. The scorer does: it takes a hunt's ranked
findings and the planted true-positive entity for that hunt, and reports whether
the true positive was found, at what rank, and the precision over the findings the
hunt actually surfaced as malicious/suspicious. This is how we measure a hunt the
way a detection engineer would - not "did it alert" but "was the real thing at the
top, and how much noise came with it".
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Callable, List, Optional

from .hunts import Finding


@dataclass
class HuntScore:
    hunt_id: str
    technique: str
    true_positive_found: bool
    rank_of_first_tp: Optional[int]       # 1-based; None if not found
    top_entity: str
    top_is_tp: bool
    n_findings: int
    precision_at_malicious: float          # of findings marked malicious, fraction that are TP
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _matcher_for(hunt_id: str, gt: dict) -> Callable[[Finding], bool]:
    """Return a predicate deciding whether a Finding is the planted TP for a hunt."""
    tp = gt["hunts"][hunt_id]["true_positive"]

    def contains(f: Finding, *vals) -> bool:
        hay = (f.entity + " " + repr(f.evidence)).lower()
        return all(str(v).lower() in hay for v in vals if v)

    if hunt_id == "H01":
        return lambda f: contains(f, tp["host"], tp["dst_domain"])
    if hunt_id == "H02":
        return lambda f: contains(f, tp["gparent"], tp["parent"], tp["child"])
    if hunt_id == "H03":
        return lambda f: f.entity == tp["user"]
    if hunt_id == "H04":
        return lambda f: contains(f, tp["host"]) and any(b in repr(f.evidence).lower() for b in tp["binaries"])
    if hunt_id == "H05":
        return lambda f: f.entity == tp["registered_domain"]
    if hunt_id == "H06":
        return lambda f: f.entity == tp["name"]
    if hunt_id == "H07":
        return lambda f: f.entity == tp["user"]
    if hunt_id == "H08":
        return lambda f: contains(f, tp["host"]) and "archive.7z" in f.entity.lower()
    return lambda f: False


def score_hunt(hunt_id: str, findings: List[Finding], gt: dict) -> HuntScore:
    meta = gt["hunts"][hunt_id]
    is_tp = _matcher_for(hunt_id, gt)
    rank = None
    for i, f in enumerate(findings, 1):
        if is_tp(f):
            rank = i
            break
    malicious = [f for f in findings if f.verdict == "malicious"]
    tp_malicious = [f for f in malicious if is_tp(f)]
    precision = (len(tp_malicious) / len(malicious)) if malicious else 0.0
    top_entity = findings[0].entity if findings else "(none)"
    note = ""
    if rank is None:
        note = "true positive not surfaced"
    elif rank > 1:
        note = f"true positive at rank {rank} (below a higher-scoring finding)"
    return HuntScore(
        hunt_id=hunt_id,
        technique=meta["technique"],
        true_positive_found=rank is not None,
        rank_of_first_tp=rank,
        top_entity=top_entity,
        top_is_tp=bool(findings) and is_tp(findings[0]),
        n_findings=len(findings),
        precision_at_malicious=round(precision, 3),
        note=note,
    )


# ---------------------------------------------------------------------------
# Program-level metrics
# ---------------------------------------------------------------------------
def _parse_iso(ts: str) -> float:
    import datetime as dt
    return dt.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc).timestamp()


def time_to_find(hunt_mod, hunt_id: str, ds, gt: dict, cadence_s: int = 86400) -> dict:
    """Replay a hunt on a daily cadence and report when it would first have found the TP.

    The hunt is re-run on Dataset.until(cutoff) for cutoff = end of each day (UTC
    midnight). The first cutoff where the TP is the #1 ranked, malicious-verdict
    finding is the "found" time. Time-to-find = found - first adversary activity
    for that hunt. Dwell = end of the dataset - first activity (how long the
    activity sat unhunted in this 14-day window).
    """
    first = _parse_iso(gt["hunts"][hunt_id]["first_activity"])
    lo, hi = ds.time_range()
    is_tp = _matcher_for(hunt_id, gt)
    # first cutoff boundary after the activity started
    cutoff = (int(first // cadence_s) + 1) * cadence_s
    found = None
    while cutoff <= hi + cadence_s:
        res = hunt_mod.run(ds.until(cutoff), top=10)
        if res and is_tp(res[0]) and res[0].verdict == "malicious":
            found = cutoff
            break
        cutoff += cadence_s
    return {
        "hunt_id": hunt_id,
        "first_activity_epoch": first,
        "dwell_hours": round((hi - first) / 3600.0, 1),
        "found_epoch": found,
        "time_to_find_hours": round((found - first) / 3600.0, 1) if found else None,
    }


def adversary_entities(gt: dict) -> set:
    """Every host/user named as a true positive anywhere in the ground truth."""
    ents = {gt.get("compromised_host"), gt.get("compromised_user")}
    for h in gt.get("hunts", {}).values():
        tp = h.get("true_positive", {})
        ents.update(v for k, v in tp.items() if k in ("host", "user"))
    ents.discard(None)
    return ents


def detection_proof(rule: dict, attack_ds, benign_ds=None, gt: dict | None = None) -> dict:
    """Fire/no-fire evidence for one graduated Sigma rule.

    attack_ds : the full dataset (benign + adversary)
    benign_ds : the benign-only dataset (same seed, adversary omitted), if built
    Counts alerts, how many touch the compromised host/user, and how many fire on
    the benign-only baseline (the false-positive count that gates graduation).
    """
    from . import detections
    src = rule["hunt_source"]
    hits = detections.evaluate_rule(rule, attack_ds.events(src))
    members = []
    for h in hits:
        members.extend(h["_members"] if "_members" in h else [h])
    tp_entities = adversary_entities(gt or {})
    on_tp = sum(1 for m in members if m.get("host") in tp_entities or m.get("user") in tp_entities)
    benign_hits = None
    if benign_ds is not None:
        benign_hits = len(detections.evaluate_rule(rule, benign_ds.events(src)))
    return {
        "rule_id": rule.get("id"),
        "title": rule.get("title"),
        "source": src,
        "alerts": len(hits),
        "events_matched": len(members),
        "events_on_adversary": on_tp,
        "fires_on_adversary": len(hits) > 0 and on_tp == len(members),
        "benign_baseline_alerts": benign_hits,
    }
