"""The eight hunts.

Each hunt module exposes:
  META    : dict with id, name, technique, data_sources, decision hint
  run(ds, top=10) -> list[Finding]   ranked, highest score first

A Finding carries the entity, a numeric score, a human explanation and the
evidence that supports it. The CLI, the scorer and the report all consume this
one shape, so a hunt is just "turn a Dataset into ranked, explained Findings".
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List


@dataclass
class Finding:
    entity: str                      # the thing being ranked (host, user, domain...)
    score: float                     # 0..100-ish; higher = more suspicious
    verdict: str                     # "malicious" | "suspicious" | "benign" | "review"
    explanation: str                 # why it scored this way
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["score"] = round(self.score, 3)
        return d


# Import order defines list/run-all order.
from . import h01_beaconing  # noqa: E402
from . import h02_lineage     # noqa: E402
from . import h03_kerberoast  # noqa: E402
from . import h04_lolbin      # noqa: E402
from . import h05_dns_tunnel  # noqa: E402
from . import h06_persistence # noqa: E402
from . import h07_logon       # noqa: E402
from . import h08_staging     # noqa: E402

HUNTS = {
    "H01": h01_beaconing,
    "H02": h02_lineage,
    "H03": h03_kerberoast,
    "H04": h04_lolbin,
    "H05": h05_dns_tunnel,
    "H06": h06_persistence,
    "H07": h07_logon,
    "H08": h08_staging,
}

ORDER = ["H01", "H02", "H03", "H04", "H05", "H06", "H07", "H08"]


def get(hunt_id: str):
    hunt_id = hunt_id.upper()
    if hunt_id not in HUNTS:
        raise KeyError(f"unknown hunt {hunt_id!r}; known: {', '.join(ORDER)}")
    return HUNTS[hunt_id]
