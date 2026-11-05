import json
import os
import subprocess
import sys

from hunt import cli

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run(*args):
    return subprocess.run([sys.executable, "-m", "hunt", *args], cwd=ROOT, capture_output=True, text=True, timeout=120)


def test_cli_list(capsys):
    assert cli.main(["list"]) == 0
    out = capsys.readouterr().out
    assert all(f"H0{i}" in out for i in range(1, 9))
    assert "T1558.003" in out


def test_cli_run_text(capsys):
    assert cli.main(["run", "H03", "--top", "3"]) == 0
    out = capsys.readouterr().out
    assert "rbaxter" in out and "distinct RC4 SPNs" in out


def test_cli_run_json_lowercase_id(capsys):
    assert cli.main(["run", "h05", "--json", "--top", "2"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["hunt_id"] == "H05"
    assert payload["findings"][0]["entity"] == "dataxfil-svc.example"
    assert len(payload["findings"]) == 2


def test_cli_run_all_writes_json(tmp_path, capsys):
    assert cli.main(["run-all", "--out", str(tmp_path)]) == 0
    files = sorted(os.listdir(tmp_path))
    assert files == [f"H0{i}.json" for i in range(1, 9)]
    h08 = json.load(open(tmp_path / "H08.json"))
    assert h08["findings"][0]["evidence"]["host"] == "WKS-0042"


def test_cli_unknown_hunt_exit_code(capsys):
    assert cli.main(["run", "H99"]) == 2
    assert "unknown hunt" in capsys.readouterr().err


def test_cli_score_subprocess():
    r = _run("score")
    assert r.returncode == 0, r.stderr
    assert "recall (planted behaviours surfaced): 8/8" in r.stdout
    assert "TP ranked #1: 8/8" in r.stdout


def test_cli_detect_subprocess():
    r = _run("detect")
    assert r.returncode == 0, r.stderr
    assert "H03-kerberoasting-rc4-burst" in r.stdout and "WKS-0042" in r.stdout


def test_cli_help():
    r = _run("--help")
    assert r.returncode == 0
    for sub in ("list", "run", "run-all", "score", "report"):
        assert sub in r.stdout
