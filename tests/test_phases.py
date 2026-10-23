from pathlib import Path

import pytest

from nmapfw.phases import run_scan
from nmapfw.validate import ValidationError

FIXTURE = Path(__file__).parent / "fixtures" / "open-ports.xml"


def test_quick_profile_runs_discovery_and_ports_with_progress(tmp_path):
    calls = []
    progress = []

    def fake_runner(targets, arguments, output_file):
        calls.append((targets, arguments))
        Path(output_file).write_bytes(FIXTURE.read_bytes())

    scan = run_scan(
        "192.0.2.10",
        permission=True,
        output_dir=tmp_path / "scan",
        audit_log=tmp_path / "audit.log",
        runner=fake_runner,
        progress_callback=lambda phase, state: progress.append((phase, state)),
    )
    assert len(calls) == 2
    assert calls[0][1] == ["-sn"]
    assert "--top-ports" in calls[1][1]
    assert scan.hosts[0].address == "192.0.2.10"
    assert ("ports", "completed") in progress
    assert "targets=192.0.2.10" in (tmp_path / "audit.log").read_text()


def test_permission_gate_precedes_scan_and_audit(tmp_path):
    with pytest.raises(ValidationError, match="Scan refused"):
        run_scan(
            "192.0.2.10",
            output_dir=tmp_path / "scan",
            audit_log=tmp_path / "audit.log",
            runner=lambda *_args: pytest.fail("runner must not be called"),
        )
    assert not (tmp_path / "audit.log").exists()


def test_failed_phase_returns_readable_partial_scan(tmp_path):
    def failing_runner(*_args):
        raise RuntimeError("not expected")

    # Runner errors outside the documented Nmap error surface should remain visible.
    with pytest.raises(RuntimeError, match="not expected"):
        run_scan(
            "192.0.2.10",
            permission=True,
            output_dir=tmp_path / "scan",
            audit_log=tmp_path / "audit.log",
            runner=failing_runner,
        )
