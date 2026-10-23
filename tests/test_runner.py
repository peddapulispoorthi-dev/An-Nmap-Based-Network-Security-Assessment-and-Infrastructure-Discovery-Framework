import subprocess

import pytest

from nmapfw.runner import NmapError, run_nmap


def test_runner_uses_argument_list_and_xml_output(tmp_path, monkeypatch):
    from nmapfw import runner

    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        (tmp_path / "scan.xml").write_text("<nmaprun/>")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(runner.shutil, "which", lambda _name: "C:\\Nmap\\nmap.exe")
    monkeypatch.setattr(runner.subprocess, "run", fake_run)
    run_nmap(["192.0.2.1"], ["-sT", "--top-ports", "100"], tmp_path / "scan.xml")
    assert captured["command"] == [
        "C:\\Nmap\\nmap.exe",
        "-sT",
        "--top-ports",
        "100",
        "-oX",
        str(tmp_path / "scan.xml"),
        "192.0.2.1",
    ]
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["timeout"] == 900


def test_runner_reports_missing_nmap_and_timeout(tmp_path, monkeypatch):
    from nmapfw import runner

    monkeypatch.setattr(runner.shutil, "which", lambda _name: None)
    with pytest.raises(NmapError, match="not found"):
        run_nmap(["192.0.2.1"], ["-sn"], tmp_path / "scan.xml")
    monkeypatch.setattr(runner.shutil, "which", lambda _name: "nmap")
    monkeypatch.setattr(
        runner.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(subprocess.TimeoutExpired("nmap", 1)),
    )
    with pytest.raises(NmapError, match="timed out"):
        run_nmap(["192.0.2.1"], ["-sn"], tmp_path / "scan.xml", timeout=1)
