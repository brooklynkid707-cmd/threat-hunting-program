import pytest

from hunt import detections, metrics
from hunt.hunts import ORDER, get

RULES = {r["id"]: r for r in detections.load_rules()}


def test_every_graduated_hunt_has_a_rule():
    graduated = {get(h).META["detection"] for h in ORDER if get(h).META["decision"] == "new detection created"}
    assert graduated == set(RULES)
    for h in ORDER:
        if get(h).META["decision"] != "new detection created":
            assert get(h).META["detection"] is None


def test_rules_have_required_sigma_fields():
    for rule_id, r in RULES.items():
        for key in ("title", "id", "status", "description", "logsource", "detection", "level", "tags",
                    "falsepositives"):
            assert key in r, (rule_id, key)
        assert "condition" in r["detection"], rule_id
        assert any(t.startswith("attack.t") for t in r["tags"]), rule_id


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_rule_fires_on_adversary_only(rule_id, ds, benign_ds, gt):
    proof = metrics.detection_proof(RULES[rule_id], ds, benign_ds, gt)
    assert proof["alerts"] >= 1
    assert proof["fires_on_adversary"], proof
    assert proof["benign_baseline_alerts"] == 0, proof


def test_kerberoast_correlation_alert_entity(ds):
    alerts = detections.evaluate_rule(RULES["H03-kerberoasting-rc4-burst"], ds.auth)
    assert [a["user"] for a in alerts] == ["rbaxter"]
    assert alerts[0]["_count"] == 9


def test_evaluator_modifiers_and_lists():
    rule = {"detection": {"sel": {"cmd|contains": "URLCACHE", "proc": ["a.exe", "certutil.exe"],
                                  "size|gte": 10}, "condition": "sel"}}
    hit = {"cmd": "certutil -urlcache -f", "proc": "CERTUTIL.EXE", "size": 10}
    miss = {"cmd": "certutil -store", "proc": "certutil.exe", "size": 10}
    assert detections.evaluate_rule(rule, [hit, miss]) == [hit]


def test_evaluator_boolean_conditions():
    rule = {"detection": {"a": {"x": 1}, "b": {"y|startswith": "svc-"}, "filter": {"z|endswith": ".tmp"},
                          "condition": "(a or b) and not filter"}}
    evs = [{"x": 1, "z": "f.txt"}, {"y": "svc-backup", "z": "f.tmp"}, {"y": "user1"}]
    assert detections.evaluate_rule(rule, evs) == [evs[0]]


def test_evaluator_of_them_and_regex():
    rule = {"detection": {"sel_a": {"p|re": r"\\perflogs\\"}, "sel_b": {"ext": "7z"},
                          "condition": "all of sel_*"}}
    assert len(detections.evaluate_rule(rule, [{"p": r"C:\PerfLogs\a.7z", "ext": "7z"},
                                               {"p": r"C:\PerfLogs\a.zip", "ext": "zip"}])) == 1
    rule["detection"]["condition"] = "1 of them"
    assert len(detections.evaluate_rule(rule, [{"ext": "7z"}, {"p": "x"}])) == 1


def test_evaluator_missing_field_never_matches():
    rule = {"detection": {"s": {"user|startswith": "svc-"}, "condition": "s"}}
    assert detections.evaluate_rule(rule, [{"host": "h"}]) == []
