import json

import pytest

from nmapfw import cli
from nmapfw.models import Host, Port, Scan
from nmapfw.storage import save_scan


def test_scan_requires_permission_and_help_for_commands(capsys):
    with pytest.raises(SystemExit) as help_exit:
        cli.main(["scan", "--help"])
    assert help_exit.value.code == 0
    help_text = capsys.readouterr().out
    assert "--i-have-permission" in help_text
    for command in ("history", "show", "diff", "report"):
        with pytest.raises(SystemExit) as command_help:
            cli.main([command, "--help"])
        assert command_help.value.code == 0


def test_scan_command_generates_reports_and_progress(tmp_path, monkeypatch, capsys):
    def fake_scan(targets, profile, **kwargs):
        kwargs["progress_callback"]("discovery", "completed")
        return Scan(
            [targets],
            profile=profile,
            scan_id=kwargs["scan_id"],
            hosts=[Host(targets, status="up", ports=[Port(22, "tcp", "open", "ssh")])],
        )

    monkeypatch.setattr(cli, "run_scan", fake_scan)
    assert cli.main(
        [
            "scan",
            "192.0.2.10",
            "--profile",
            "quick",
            "--i-have-permission",
            "--out",
            str(tmp_path),
        ]
    ) == 0
    output = capsys.readouterr().out
    assert "[discovery] completed" in output
    assert "Risk: 0/100 (Low)" in output
    assert list(tmp_path.glob("*/report.html"))


def test_history_show_diff_and_report_commands(tmp_path, capsys):
    database = tmp_path / "history.sqlite3"
    first = Scan(
        ["192.0.2.1"],
        scan_id="first",
        hosts=[Host("192.0.2.1", ports=[Port(22, "tcp", "open", "ssh")])],
    )
    second = Scan(
        ["192.0.2.1"],
        scan_id="second",
        hosts=[Host("192.0.2.1", ports=[Port(22, "tcp", "open", "ssh"), Port(80, "tcp", "open", "http")])],
    )
    save_scan(first, database)
    save_scan(second, database)
    database_option = ["--database", str(database)]
    assert cli.main(["history", *database_option]) == 0
    assert "first" in capsys.readouterr().out
    assert cli.main(["show", "first", *database_option]) == 0
    assert json.loads(capsys.readouterr().out)["scan_id"] == "first"
    assert cli.main(["diff", "first", "second", *database_option]) == 0
    assert '"port": 80' in capsys.readouterr().out
    output_path = tmp_path / "report.html"
    assert cli.main(["report", "first", "--format", "html", "--out", str(output_path), *database_option]) == 0
    assert "<!doctype html>" in output_path.read_text()
