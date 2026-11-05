"""Each hunt ranks the planted adversary #1 and keeps the documented look-alikes benign."""

import pytest

from hunt import metrics
from hunt.hunts import ORDER, Finding, get
from hunt.hunts import h01_beaconing


def _verdicts(findings):
    return {f.entity: f.verdict for f in findings}


@pytest.mark.parametrize("hunt_id", ORDER)
def test_planted_entity_ranked_first_and_only_tp_malicious(hunt_id, results, gt):
    score = metrics.score_hunt(hunt_id, results[hunt_id], gt)
    assert score.rank_of_first_tp == 1, score
    assert results[hunt_id][0].verdict == "malicious"
    assert score.precision_at_malicious == 1.0, score


def test_findings_explained_sorted_bounded_with_fp_review(ds, results):
    for hunt_id in ORDER:
        fs = results[hunt_id]
        assert all(isinstance(f, Finding) and f.explanation and f.evidence for f in fs), hunt_id
        assert [f.score for f in fs] == sorted((f.score for f in fs), reverse=True), hunt_id
        assert all(0 <= f.score <= 100 for f in fs), hunt_id
        notes = get(hunt_id).fp_review(ds, fs)
        assert notes and all(isinstance(n, str) and len(n) > 20 for n in notes), hunt_id


def test_h01_implant_statistics(results):
    top = results["H01"][0]
    ev = top.evidence
    assert ev["dst_domain"] == "cdn-sync-07.telemetry-edge.example"
    assert 270 <= ev["median_interval_s"] <= 330          # ~300 s sleep
    assert ev["robust_cv"] < 0.25                          # 20% jitter still tight
    assert ev["in_band_fraction"] > 0.95
    assert ev["bytes_out_cv"] < 0.1


def test_h01_update_agent_and_sanctioned_beacons_excluded(ds, results):
    for f in results["H01"]:
        if f.evidence.get("sanctioned"):
            assert f.verdict == "benign" and f.score < 10
    profiles = {p["domain"]: p for p in h01_beaconing.lookalike_profiles(ds)}
    upd = profiles["updates.contoso-software.example"]
    assert upd["robust_cv"] > 0.3            # hourly with heavy jitter: high CV
    # NTP and APM are MORE regular than the implant - only the inventory suppresses them
    assert profiles["time.ntp-pool.example"]["raw_score"] > results["H01"][0].score
    assert profiles["sync.collab-suite.example"]["raw_score"] < 5


def test_h01_naive_frequency_fails(ds, results):
    naive = h01_beaconing.naive_frequency_ranking(ds, top=10000)
    assert "sync.collab-suite.example" in naive[0][0]
    implant_rank = [e for e, _ in naive].index(results["H01"][0].entity) + 1
    assert implant_rank > 10


def test_h02_admin_tools_benign(results):
    for f in results["H02"]:
        if any(t in f.entity for t in ("psexec", "nmap", "procmon", "wireshark")):
            assert f.verdict == "benign" and f.score < 5


def test_h03_legacy_rc4_account_not_flagged(results):
    users = {f.entity for f in results["H03"]}
    assert "svc-legacy" not in users
    assert results["H03"][0].evidence["peak_distinct_rc4_spns"] == 9
    assert results["H03"][0].evidence["burst_span_s"] <= 180


def test_h04_benign_certutil_not_matched(results):
    cmds = [f.evidence["cmdline"] for f in results["H04"]]
    assert len(cmds) == 3
    assert not any("-store" in c or "-verify" in c or "Program Files" in c for c in cmds)


def test_h05_cdns_suppressed(results):
    v = _verdicts(results["H05"])
    assert v["akamai-cdn.example"] == "benign"
    assert v["cloudfront-dist.example"] == "benign"
    top = results["H05"][0].evidence
    assert top["mean_entropy_bits"] > 4.0 and top["mean_label_length"] > 25


def test_h06_rare_but_legit_services_benign(results):
    v = _verdicts(results["H06"])
    assert v["FinanceLedger Sync"] == "benign"
    assert v["\\NW-IT\\InventoryScan"] == "benign"
    assert results["H06"][0].evidence["host_count"] == 1


def test_h07_humans_and_legit_service_accounts_excluded(results):
    users = {f.entity for f in results["H07"]}
    assert users == {"svc-backup"}
    assert results["H07"][0].evidence["anomaly"]["logon_type"] == 10


def test_h08_backup_job_suppressed(results):
    for f in results["H08"][1:]:
        assert f.evidence["host"] == "SRV-0001" and not f.evidence["external"]
        assert f.verdict == "benign"
    top = results["H08"][0].evidence
    assert top["external"] and top["suspicious_path"]


@pytest.mark.parametrize("hunt_id", ORDER)
def test_hunts_quiet_on_benign_only_baseline(hunt_id, benign_ds):
    """With the adversary removed, no hunt calls anything malicious."""
    fs = get(hunt_id).run(benign_ds, top=10)
    assert not [f.entity for f in fs if f.verdict == "malicious"]



def test_unknown_hunt_id():
    with pytest.raises(KeyError):
        get("H42")
