"""Dataset loader for the Northwind Logistics synthetic telemetry.

The generator (scripts/generate_dataset.py) writes one gzip-compressed JSON Lines
file per source into data/. Each line is one event (a dict). This module loads
them lazily-ish into memory (the whole 14-day set is a few MB) and exposes a
small typed-ish accessor so the hunts don't each re-implement file handling.

Sources
-------
process   process creation (Sysmon event id 1 shape)
network   outbound network connections / proxy records (bytes, ua, domain, dst)
dns       DNS queries (qname, qtype)
auth      Windows security auth events (4624/4625/4769/4672)
service   service + scheduled-task creation (7045/4698)
files     file-creation summary rows (archives)
"""

from __future__ import annotations

import gzip
import json
import os
from typing import Dict, Iterator, List

SOURCES = ["process", "network", "dns", "auth", "service", "files"]

_DEFAULT_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def data_dir(path: str | None = None) -> str:
    """Resolve the data directory (explicit arg, $HUNT_DATA_DIR, or repo data/)."""
    if path:
        return path
    return os.environ.get("HUNT_DATA_DIR", _DEFAULT_DATA_DIR)


def _source_path(source: str, path: str | None = None) -> str:
    return os.path.join(data_dir(path), f"{source}.jsonl.gz")


def iter_source(source: str, path: str | None = None) -> Iterator[dict]:
    """Yield every event dict from one source file."""
    fp = _source_path(source, path)
    if not os.path.exists(fp):
        raise FileNotFoundError(
            f"missing data source {source!r} at {fp}; run 'make data' or "
            f"'python scripts/generate_dataset.py' first"
        )
    with gzip.open(fp, "rt", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)


class Dataset:
    """In-memory view of all sources. Cheap to construct; loads on first access."""

    def __init__(self, path: str | None = None):
        self.path = data_dir(path)
        self._cache: Dict[str, List[dict]] = {}

    def events(self, source: str) -> List[dict]:
        if source not in SOURCES:
            raise KeyError(f"unknown source {source!r}; known: {SOURCES}")
        if source not in self._cache:
            self._cache[source] = list(iter_source(source, self.path))
        return self._cache[source]

    # convenience accessors -------------------------------------------------
    @property
    def process(self) -> List[dict]:
        return self.events("process")

    @property
    def network(self) -> List[dict]:
        return self.events("network")

    @property
    def dns(self) -> List[dict]:
        return self.events("dns")

    @property
    def auth(self) -> List[dict]:
        return self.events("auth")

    @property
    def service(self) -> List[dict]:
        return self.events("service")

    @property
    def files(self) -> List[dict]:
        return self.events("files")

    def counts(self) -> Dict[str, int]:
        return {s: len(self.events(s)) for s in SOURCES}

    def time_range(self):
        """(min_epoch, max_epoch) across all sources."""
        lo, hi = None, None
        for s in SOURCES:
            evs = self.events(s)
            if evs:
                a, b = evs[0]["epoch"], evs[-1]["epoch"]
                lo = a if lo is None else min(lo, a)
                hi = b if hi is None else max(hi, b)
        return lo, hi

    def until(self, cutoff_epoch: float) -> "Dataset":
        """A view containing only events at or before `cutoff_epoch`.

        Used to replay a hunt as if it had been run on an earlier date (the
        "time-to-find if this hunt ran daily" metric). Events are time-sorted on
        disk, so this is a cheap prefix filter.
        """
        view = Dataset(self.path)
        for s in SOURCES:
            view._cache[s] = [e for e in self.events(s) if e["epoch"] <= cutoff_epoch]
        return view


def load(path: str | None = None) -> Dataset:
    """Return a Dataset for the given (or default) data directory."""
    return Dataset(path)


def load_ground_truth(path: str | None = None) -> dict:
    """Load ground_truth.json. Only tests and the `score` command use this."""
    fp = os.path.join(data_dir(path), "ground_truth.json")
    with open(fp, "r", encoding="utf-8") as fh:
        return json.load(fh)


def benign_dataset() -> Dataset:
    """Build the benign-only baseline in memory (same seed, adversary omitted).

    The generator draws the adversary last, so the benign events here are
    identical to the benign events in data/. Graduated detections are checked
    against this view: a rule that alerts here would be a false positive.
    Takes ~2s; nothing is written to disk.
    """
    import importlib.util

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    spec = importlib.util.spec_from_file_location(
        "_nw_generate_dataset", os.path.join(root, "scripts", "generate_dataset.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    gen = mod.build(benign_only=True)
    view = Dataset(path=os.path.join(root, "data"))
    for s in SOURCES:
        view._cache[s] = sorted(gen.sources[s], key=lambda e: e["epoch"])
    return view
