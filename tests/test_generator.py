import hashlib
import os
import subprocess
import sys

from hunt import data

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _sha(fp):
    with open(fp, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def test_generator_reproduces_committed_dataset(tmp_path):
    env = dict(os.environ, PYTHONHASHSEED="12345")    # prove output does not depend on hash order
    subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "generate_dataset.py"), "--out", str(tmp_path)],
                   check=True, capture_output=True, env=env, timeout=60)
    for name in [f"{s}.jsonl.gz" for s in data.SOURCES] + ["ground_truth.json"]:
        assert _sha(tmp_path / name) == _sha(os.path.join(ROOT, "data", name)), name


def test_benign_only_mode_has_no_adversary(tmp_path):
    subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "generate_dataset.py"), "--out", str(tmp_path),
                    "--benign-only"], check=True, capture_output=True, timeout=60)
    assert not (tmp_path / "ground_truth.json").exists()
    d = data.load(str(tmp_path))
    assert not [e for e in d.network if e["dst_ip"].startswith("203.0.113.")]
    assert not [e for e in d.service if e.get("name") == "WinSyncHelper"]


def test_benign_events_identical_with_and_without_adversary(ds, benign_ds):
    """The adversary is drawn last, so the benign baseline is the same in both datasets."""
    for s in data.SOURCES:
        full = [e for e in ds.events(s) if e.get("host") != "WKS-0042" and e.get("user") != "svc-backup"]
        base = [e for e in benign_ds.events(s) if e.get("host") != "WKS-0042" and e.get("user") != "svc-backup"]
        assert full == base, s


def test_ground_truth_covers_every_hunt(gt):
    assert sorted(gt["hunts"]) == [f"H0{i}" for i in range(1, 9)]
    assert gt["all_synthetic"] is True
    for h in gt["hunts"].values():
        assert h["true_positive"] and h["benign_lookalikes"] and h["first_activity"]
