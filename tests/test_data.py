import os

from hunt import data


def test_all_sources_load(ds):
    counts = ds.counts()
    assert set(counts) == set(data.SOURCES)
    assert all(v > 0 for v in counts.values())
    assert counts["network"] > 50_000


def test_inventory_shape(ds):
    hosts = {e["host"] for e in ds.process}
    assert len([h for h in hosts if h.startswith("WKS-")]) == 60
    assert {"SRV-0001", "SRV-0002", "SRV-0003", "DC-0001", "DC-0002"} <= hosts
    users = {e["user"] for e in ds.auth}
    assert 65 <= len(users) <= 80


def test_fourteen_days_sorted(ds):
    lo, hi = ds.time_range()
    assert 13 * 86400 < hi - lo <= 14 * 86400
    epochs = [e["epoch"] for e in ds.network]
    assert epochs == sorted(epochs)


def test_weekends_are_quiet(ds):
    import datetime as dt
    per_day = {}
    for e in ds.process:
        d = dt.datetime.fromtimestamp(e["epoch"], tz=dt.timezone.utc).date()
        per_day[d] = per_day.get(d, 0) + 1
    weekday = [v for d, v in per_day.items() if d.weekday() < 5]
    weekend = [v for d, v in per_day.items() if d.weekday() >= 5]
    assert max(weekend) < min(weekday) / 2


def test_dataset_size_under_limit():
    total = sum(os.path.getsize(os.path.join(data.data_dir(), f"{s}.jsonl.gz")) for s in data.SOURCES)
    assert total < 15_000_000


def test_safety_only_documentation_and_private_ips(ds):
    import ipaddress
    doc = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    for e in ds.network:
        ip = ipaddress.ip_address(e["dst_ip"])
        assert ip.is_private or any(ip in n for n in doc), e["dst_ip"]
    for e in ds.dns:
        assert e["qname"].endswith((".example", ".test")), e["qname"]


def test_until_view_is_a_prefix(ds):
    lo, hi = ds.time_range()
    mid = lo + (hi - lo) / 2
    view = ds.until(mid)
    assert 0 < len(view.network) < len(ds.network)
    assert all(e["epoch"] <= mid for e in view.auth)


def test_hunts_never_read_ground_truth():
    import glob
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for fp in glob.glob(os.path.join(root, "hunt", "hunts", "*.py")):
        src = open(fp, encoding="utf-8").read()
        assert "ground_truth" not in src and "load_ground_truth" not in src, fp


def test_unknown_source_raises(ds):
    import pytest
    with pytest.raises(KeyError):
        ds.events("netflow")


def test_missing_data_dir_gives_clear_error(tmp_path):
    import pytest
    with pytest.raises(FileNotFoundError, match="make data"):
        data.load(str(tmp_path)).process
