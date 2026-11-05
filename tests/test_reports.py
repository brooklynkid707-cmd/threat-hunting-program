"""Committed results.md / program report / examples match a fresh regeneration."""

import json
import os

import pytest

from hunt import report
from hunt.hunts import ORDER


@pytest.fixture(scope="module")
def regenerated(ds, benign_ds, tmp_path_factory):
    out = tmp_path_factory.mktemp("reports")
    built = report.build_all(ds, benign_ds=benign_ds)
    report.write_reports(built, hunts_dir=str(out / "hunts"), program_dir=str(out / "program"),
                         examples_dir=str(out / "examples"))
    return out


def test_committed_results_md_is_current(regenerated):
    for hunt_id in ORDER:
        folder = report.HUNT_FOLDERS[hunt_id]
        fresh = (regenerated / "hunts" / folder / "results.md").read_text(encoding="utf-8")
        committed = open(os.path.join(report.HUNTS_DIR, folder, "results.md"), encoding="utf-8").read()
        assert fresh == committed, f"run `python -m hunt report` to refresh {folder}/results.md"


def test_committed_program_report_is_current(regenerated):
    fresh = (regenerated / "program" / "program_report.md").read_text(encoding="utf-8")
    committed = open(os.path.join(report.PROGRAM_DIR, "program_report.md"), encoding="utf-8").read()
    assert fresh == committed


def test_committed_examples_json_is_current(regenerated):
    for name in ("findings.json", "scores.json"):
        fresh = json.loads((regenerated / "examples" / name).read_text(encoding="utf-8"))
        committed = json.load(open(os.path.join(report.EXAMPLES_DIR, name), encoding="utf-8"))
        assert fresh == committed, name


def test_results_md_structure(regenerated):
    for h in ORDER:
        text = (regenerated / "hunts" / report.HUNT_FOLDERS[h] / "results.md").read_text(encoding="utf-8")
        for section in ("## What was found", "ranked outliers", "## False-positive review",
                        "## Decision", "## Scored against ground truth"):
            assert section in text, (h, section)


def test_program_report_contents(regenerated):
    text = (regenerated / "program" / "program_report.md").read_text(encoding="utf-8")
    assert "Hunt-to-detection conversion rate | 75.0%" in text
    assert "| H01 | T1071.001 | `WKS-0042 -> cdn-sync-07.telemetry-edge.example` | yes | 1 |" in text
    assert "Dwell vs time-to-find" in text and "Data gaps" in text


def test_hunt_folders_complete_in_peak_format():
    for hunt_id in ORDER:
        folder = os.path.join(report.HUNTS_DIR, report.HUNT_FOLDERS[hunt_id])
        for fn in ("hypothesis.md", "query.kql", "query.spl", "results.md"):
            assert os.path.getsize(os.path.join(folder, fn)) > 300, (hunt_id, fn)
        hyp = open(os.path.join(folder, "hypothesis.md"), encoding="utf-8").read()
        for section in ("## Prepare", "## Execute", "## Act with Knowledge", "**Hypothesis.**",
                        "**Assumptions.**", "**Scope.**", "**Detection decision"):
            assert section in hyp, (hunt_id, section)
        # the decision written in the hypothesis matches the one the code reports
        from hunt.hunts import get
        assert get(hunt_id).META["decision"] in hyp, hunt_id
