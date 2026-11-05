"""Graduated detections and a minimal Sigma evaluator.

Hunts that produce a durable, low-false-positive signal "graduate" into a
detection. We express those as Sigma rules (the vendor-neutral detection format)
under rules/, and ship a small evaluator here that runs a Sigma detection against
the synthetic events so the tests can prove each rule fires on the adversary and
stays quiet on the benign baseline. This closes the hunt-to-detection loop: a
hunt is only worth graduating if its detection actually distinguishes the
intrusion from the look-alikes.

The evaluator supports the subset of Sigma used by these rules:
  detection.<selection> : {field: value | [values] | field|modifier: value}
  modifiers: contains, startswith, endswith, re, gte, lte, gt, lt
  condition : boolean combination of selection names with and/or/not and
              "N of them" / "all of them" / "1 of selection_*"
It is intentionally small and readable, not a full Sigma engine.
"""

from __future__ import annotations

import os
import re as _re
from typing import Any, Dict, Iterable, List

import yaml

RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")


def load_rules(rules_dir: str | None = None) -> List[dict]:
    rules_dir = rules_dir or RULES_DIR
    rules = []
    for fn in sorted(os.listdir(rules_dir)):
        if fn.endswith((".yml", ".yaml")):
            with open(os.path.join(rules_dir, fn), "r", encoding="utf-8") as fh:
                rule = yaml.safe_load(fh)
                rule["_file"] = fn
                rules.append(rule)
    return rules


def _match_value(event_val: Any, expected: Any, modifier: str | None) -> bool:
    if event_val is None:
        return False
    ev = str(event_val)
    def one(exp):
        exp_s = str(exp)
        if modifier is None:
            # case-insensitive exact for strings, loose for numbers
            if isinstance(event_val, (int, float)) and not isinstance(event_val, bool):
                try:
                    return float(event_val) == float(exp)
                except ValueError:
                    return False
            return ev.lower() == exp_s.lower()
        if modifier == "contains":
            return exp_s.lower() in ev.lower()
        if modifier == "startswith":
            return ev.lower().startswith(exp_s.lower())
        if modifier == "endswith":
            return ev.lower().endswith(exp_s.lower())
        if modifier == "re":
            return bool(_re.search(exp_s, ev, _re.I))
        if modifier in ("gt", "gte", "lt", "lte"):
            try:
                a, b = float(event_val), float(exp)
            except ValueError:
                return False
            return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[modifier]
        return False
    if isinstance(expected, list):
        return any(one(e) for e in expected)  # a list is an OR of values
    return one(expected)


def _match_selection(event: dict, selection: dict) -> bool:
    # a selection is an AND over its field criteria
    for field, expected in selection.items():
        modifier = None
        base = field
        if "|" in field:
            base, modifier = field.split("|", 1)
        if not _match_value(event.get(base), expected, modifier):
            return False
    return True


def _eval_condition(condition: str, sel_results: Dict[str, bool], selections: Dict[str, Any]) -> bool:
    cond = condition.strip()

    # "all of them" / "N of them"
    m = _re.fullmatch(r"all of them", cond, _re.I)
    if m:
        return all(sel_results.values())
    m = _re.fullmatch(r"(\d+) of them", cond, _re.I)
    if m:
        return sum(1 for v in sel_results.values() if v) >= int(m.group(1))
    m = _re.fullmatch(r"(\d+) of (\w+)\*", cond, _re.I)
    if m:
        n = int(m.group(1))
        pref = m.group(2)
        hits = sum(1 for k, v in sel_results.items() if k.startswith(pref) and v)
        return hits >= n
    m = _re.fullmatch(r"all of (\w+)\*", cond, _re.I)
    if m:
        pref = m.group(1)
        keys = [k for k in sel_results if k.startswith(pref)]
        return bool(keys) and all(sel_results[k] for k in keys)

    # boolean expression over selection names
    expr = cond
    # replace "not X" and bare names with python booleans; keep and/or
    tokens = _re.findall(r"\(|\)|\band\b|\bor\b|\bnot\b|[A-Za-z_][A-Za-z0-9_]*", cond)
    py = []
    for tok in tokens:
        low = tok.lower()
        if low in ("and", "or", "not") or tok in ("(", ")"):
            py.append(low if low in ("and", "or", "not") else tok)
        else:
            py.append(str(bool(sel_results.get(tok, False))))
    try:
        return bool(eval(" ".join(py), {"__builtins__": {}}, {}))  # noqa: S307 - constrained tokens only
    except Exception:
        return False


def _simple_matches(rule: dict, events: List[dict]) -> List[dict]:
    detection = rule.get("detection", {})
    condition = detection.get("condition", "")
    selections = {k: v for k, v in detection.items() if k != "condition"}
    matches = []
    for ev in events:
        sel_results = {name: _match_selection(ev, sel) for name, sel in selections.items()}
        if _eval_condition(condition, sel_results, selections):
            matches.append(ev)
    return matches


def _evaluate_correlation(rule: dict, events: List[dict]) -> List[dict]:
    """Threshold/aggregation detection over a sliding time window.

    Supports a small subset of Sigma correlation:
      correlation.type   : "value_count" (distinct values of `field`) or
                           "event_count" (number of matching events)
      correlation.group_by : list of fields forming the group key
      correlation.timespan : window in seconds
      correlation.field    : the field counted (value_count)
      correlation.condition: {gte|gt|lte|lt: N}

    Returns one synthesized alert dict per qualifying window, carrying the
    group-by fields, the count and the member events - so tests can assert both
    that it fired and on which entity.
    """
    corr = rule["correlation"]
    base = _simple_matches(rule, events)
    base.sort(key=lambda e: e.get("epoch", 0))
    group_by = corr.get("group_by", [])
    timespan = float(corr.get("timespan", 600))
    ctype = corr.get("type", "event_count")
    field = corr.get("field")
    cond = corr.get("condition", {})

    # bucket by group key
    groups: Dict[tuple, List[dict]] = {}
    for ev in base:
        key = tuple(ev.get(g) for g in group_by)
        groups.setdefault(key, []).append(ev)

    def passes(count: int) -> bool:
        for op, n in cond.items():
            if op == "gte" and not count >= n:
                return False
            if op == "gt" and not count > n:
                return False
            if op == "lte" and not count <= n:
                return False
            if op == "lt" and not count < n:
                return False
        return True

    alerts = []
    for key, evs in groups.items():
        evs.sort(key=lambda e: e.get("epoch", 0))
        best = None
        for i in range(len(evs)):
            window = [e for e in evs if 0 <= e.get("epoch", 0) - evs[i].get("epoch", 0) <= timespan]
            if ctype == "value_count":
                count = len({e.get(field) for e in window})
            else:
                count = len(window)
            if passes(count) and (best is None or count > best[0]):
                best = (count, window)
        if best:
            alert = {g: key[j] for j, g in enumerate(group_by)}
            alert["_count"] = best[0]
            alert["_members"] = best[1]
            alert["_rule"] = rule.get("id")
            alerts.append(alert)
    return alerts


def evaluate_rule(rule: dict, events: Iterable[dict]) -> List[dict]:
    """Return matches for a rule: events (simple) or alerts (correlation)."""
    events = list(events)
    if "correlation" in rule:
        return _evaluate_correlation(rule, events)
    return _simple_matches(rule, events)


def evaluate_all(events: Iterable[dict], rules_dir: str | None = None) -> Dict[str, List[dict]]:
    events = list(events)
    out = {}
    for rule in load_rules(rules_dir):
        out[rule.get("id", rule["_file"])] = evaluate_rule(rule, events)
    return out
