"""Command-line interface: python -m hunt <subcommand>."""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from typing import List, Optional

from . import __version__, data, detections, metrics, report
from .hunts import ORDER, get


def _ds(args):
    return data.load(getattr(args, "data", None))


def cmd_list(args) -> int:
    print(f"{'ID':4} {'Technique':10} {'Decision':34} Name")
    for h in ORDER:
        m = get(h).META
        print(f"{h:4} {m['technique']:10} {m['decision']:34} {m['name']}")
    return 0


def cmd_run(args) -> int:
    mod = get(args.hunt_id)
    ds = _ds(args)
    findings = mod.run(ds, top=args.top)
    if args.json:
        print(json.dumps({"hunt_id": mod.META["id"], "findings": [f.to_dict() for f in findings]},
                         indent=2, sort_keys=True))
        return 0
    m = mod.META
    print(f"{m['id']}  {m['name']}  [{m['technique']}]")
    print(f"data: {', '.join(m['data_sources'])}   entity: {m['entity']}")
    print()
    print(f"{'#':>2}  {'score':>6}  {'verdict':10}  entity")
    for i, f in enumerate(findings, 1):
        print(f"{i:>2}  {f.score:6.1f}  {f.verdict:10}  {f.entity}")
        print(f"{'':22}{f.explanation}")
    return 0


def cmd_run_all(args) -> int:
    ds = _ds(args)
    os.makedirs(args.out, exist_ok=True)
    for h in ORDER:
        mod = get(h)
        findings = mod.run(ds, top=args.top)
        res = {"hunt_id": h, "meta": mod.META, "findings": [f.to_dict() for f in findings],
               "fp_review": mod.fp_review(ds, findings)}
        fp = os.path.join(args.out, f"{h}.json")
        with open(fp, "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=2, sort_keys=True)
            fh.write("\n")
        top = findings[0] if findings else None
        print(f"{h}  {len(findings):2d} findings  top: {top.entity if top else '-'}"
              f"  ({top.score:.1f}, {top.verdict})" if top else f"{h}  0 findings")
    print(f"wrote {len(ORDER)} JSON files to {args.out}")
    return 0


def cmd_score(args) -> int:
    ds = _ds(args)
    gt = data.load_ground_truth(ds.path)
    rows = []
    for h in ORDER:
        s = metrics.score_hunt(h, get(h).run(ds, top=args.top), gt)
        rows.append(s)
    if args.json:
        print(json.dumps([r.to_dict() for r in rows], indent=2, sort_keys=True))
        return 0
    print(f"{'Hunt':4}  {'Technique':10}  {'TP found':8}  {'Rank':>4}  {'Precision':>9}  Top-ranked entity")
    for r in rows:
        print(f"{r.hunt_id:4}  {r.technique:10}  {'yes' if r.true_positive_found else 'no':8}  "
              f"{r.rank_of_first_tp or '-':>4}  {r.precision_at_malicious:9.2f}  {r.top_entity}")
    found = sum(1 for r in rows if r.true_positive_found)
    at1 = sum(1 for r in rows if r.rank_of_first_tp == 1)
    recall = found / len(rows)
    print()
    print(f"recall (planted behaviours surfaced): {found}/{len(rows)} = {recall:.2f}   "
          f"TP ranked #1: {at1}/{len(rows)}   "
          f"mean precision: {math.fsum(r.precision_at_malicious for r in rows)/len(rows):.2f}")
    return 0 if found == len(rows) else 1


def cmd_report(args) -> int:
    ds = _ds(args)
    benign = data.benign_dataset() if not args.no_benign else None
    built = report.build_all(ds, benign_ds=benign)
    written = report.write_reports(built)
    s = built["summary"]
    for fp in written:
        print(f"wrote {os.path.relpath(fp, report.REPO_ROOT)}")
    print()
    print(f"hunts executed {s['hunts_executed']}  true positives {s['true_positives']}  "
          f"detections created {len(s['detections_created'])}  "
          f"conversion {s['conversion_rate']:.0%}  data-gap hunts {len(s['data_gap_hunts'])}")
    print(f"mean dwell {s['mean_dwell_hours']:.1f} h vs mean time-to-find (daily cadence) "
          f"{s['mean_time_to_find_hours']:.1f} h")
    return 0


def cmd_detect(args) -> int:
    ds = _ds(args)
    for rule in detections.load_rules():
        hits = detections.evaluate_rule(rule, ds.events(rule["hunt_source"]))
        ents = set()
        for h in hits:
            for m in h.get("_members", [h]):
                ents.add(m.get("host") or "-")
        print(f"{rule['id']:40} {len(hits):3d} alert(s)  hosts: {', '.join(sorted(ents)) or '-'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m hunt",
                                description="Hypothesis-driven threat hunting program (synthetic Northwind dataset).")
    p.add_argument("--version", action="version", version=f"hunt {__version__}")
    p.add_argument("--data", help="data directory (default: repo data/ or $HUNT_DATA_DIR)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list the hunts").set_defaults(func=cmd_list)

    r = sub.add_parser("run", help="run one hunt and print ranked findings")
    r.add_argument("hunt_id", help="H01..H08")
    r.add_argument("--top", type=int, default=10)
    r.add_argument("--json", action="store_true", help="JSON output")
    r.set_defaults(func=cmd_run)

    ra = sub.add_parser("run-all", help="run every hunt and write JSON findings")
    ra.add_argument("--out", default="output")
    ra.add_argument("--top", type=int, default=10)
    ra.set_defaults(func=cmd_run_all)

    s = sub.add_parser("score", help="score each hunt against ground truth")
    s.add_argument("--top", type=int, default=10)
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_score)

    rp = sub.add_parser("report", help="regenerate hunts/*/results.md, program report and examples/")
    rp.add_argument("--no-benign", action="store_true", help="skip the benign-only detection check")
    rp.set_defaults(func=cmd_report)

    d = sub.add_parser("detect", help="run the graduated Sigma rules over the dataset")
    d.set_defaults(func=cmd_detect)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (KeyError, FileNotFoundError) as e:
        print(f"error: {e.args[0] if e.args else e}", file=sys.stderr)
        return 2
