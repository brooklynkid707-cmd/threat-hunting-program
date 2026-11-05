import pytest
import yaml

from hunt import metrics, report
from hunt.hunts import ORDER, Finding, get


def test_score_all_hunts_perfect(results, gt):
    scores = [metrics.score_hunt(h, results[h], gt) for h in ORDER]
    assert all(s.true_positive_found and s.top_is_tp for s in scores)
    assert {s.technique for s in scores} == {gt["hunts"][h]["technique"] for h in ORDER}


def test_score_reports_rank_when_tp_is_not_first(gt):
    decoy = Finding("WKS-0001 -> news.example", 90, "malicious", "x", {"host": "WKS-0001"})
    tp = Finding("WKS-0042 -> cdn-sync-07.telemetry-edge.example", 80, "malicious", "x",
                 {"host": "WKS-0042", "dst_domain": "cdn-sync-07.telemetry-edge.example"})
    s = metrics.score_hunt("H01", [decoy, tp], gt)
    assert s.rank_of_first_tp == 2 and not s.top_is_tp
    assert s.precision_at_malicious == 0.5
    assert "rank 2" in s.note


def test_score_handles_miss(gt):
    s = metrics.score_hunt("H03", [], gt)
    assert not s.true_positive_found and s.rank_of_first_tp is None
    assert s.top_entity == "(none)"


def test_time_to_find_shorter_than_dwell(ds, gt):
    for hunt_id in ("H01", "H03", "H08"):
        t = metrics.time_to_find(get(hunt_id), hunt_id, ds, gt)
        assert t["time_to_find_hours"] is not None, hunt_id
        assert 0 < t["time_to_find_hours"] <= 24, hunt_id
        assert t["dwell_hours"] > t["time_to_find_hours"], hunt_id


def test_backlog_priorities_follow_formula():
    with open(f"{report.PROGRAM_DIR}/backlog.yaml", encoding="utf-8") as fh:
        b = yaml.safe_load(fh)
    executed = {h["id"] for h in b["hunts"] if h["status"] == "executed"}
    assert executed == set(ORDER)
    for h in b["hunts"]:
        expected = h["threat_intel_relevance"] * h["data_availability"] * (6 - h["effort"]) / 5
        assert h["priority"] == pytest.approx(expected, abs=0.05), h["id"]
        if h["status"] == "blocked-data-gap":
            assert h.get("data_gap")


def test_program_summary_metrics(ds, gt):
    built = report.build_all(ds)
    s = built["summary"]
    assert s["hunts_executed"] == 8 and s["true_positives"] == 8
    assert s["detections_created"] == ["H02", "H03", "H04", "H06", "H07", "H08"]
    assert s["data_gap_hunts"] == ["H05"]
    assert s["conversion_rate"] == pytest.approx(0.75)
    assert s["mean_time_to_find_hours"] < s["mean_dwell_hours"]
