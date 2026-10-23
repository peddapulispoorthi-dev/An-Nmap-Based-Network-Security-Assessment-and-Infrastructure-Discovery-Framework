"""SQLite persistence for scan history."""

import json
import sqlite3
from dataclasses import asdict
from pathlib import Path
from typing import Any

from nmapfw.config import DEFAULT_DATABASE
from nmapfw.models import Finding, Host, Port, Scan


def _connect(database: str | Path) -> sqlite3.Connection:
    """Open a SQLite connection and ensure the schema exists."""
    path = Path(database)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT,
            profile TEXT NOT NULL, targets TEXT NOT NULL, status TEXT NOT NULL,
            risk_score INTEGER NOT NULL, risk_label TEXT NOT NULL, error TEXT NOT NULL,
            payload TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS hosts (
            scan_id TEXT NOT NULL, address TEXT NOT NULL, payload TEXT NOT NULL,
            PRIMARY KEY (scan_id, address),
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS ports (
            scan_id TEXT NOT NULL, address TEXT NOT NULL, protocol TEXT NOT NULL,
            number INTEGER NOT NULL, payload TEXT NOT NULL,
            PRIMARY KEY (scan_id, address, protocol, number),
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS findings (
            scan_id TEXT NOT NULL, address TEXT NOT NULL, finding_index INTEGER NOT NULL,
            payload TEXT NOT NULL,
            PRIMARY KEY (scan_id, address, finding_index),
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
        );
        """
    )
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def save_scan(scan: Scan, database: str | Path = DEFAULT_DATABASE) -> None:
    """Persist a scan and its hosts, ports, and findings transactionally."""
    payload = json.dumps(asdict(scan), separators=(",", ":"))
    with _connect(database) as connection:
        connection.execute(
            """INSERT OR REPLACE INTO scans
            (scan_id, started_at, finished_at, profile, targets, status, risk_score,
             risk_label, error, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan.scan_id,
                scan.started_at,
                scan.finished_at,
                scan.profile,
                json.dumps(scan.targets),
                scan.status,
                scan.risk_score,
                scan.risk_label,
                scan.error,
                payload,
            ),
        )
        for table in ("hosts", "ports", "findings"):
            connection.execute(f"DELETE FROM {table} WHERE scan_id = ?", (scan.scan_id,))
        for host in scan.hosts:
            connection.execute(
                "INSERT INTO hosts VALUES (?, ?, ?)",
                (scan.scan_id, host.address, json.dumps(asdict(host))),
            )
            for port in host.ports:
                connection.execute(
                    "INSERT INTO ports VALUES (?, ?, ?, ?, ?)",
                    (scan.scan_id, host.address, port.protocol, port.number, json.dumps(asdict(port))),
                )
            for index, finding in enumerate(host.findings):
                connection.execute(
                    "INSERT INTO findings VALUES (?, ?, ?, ?)",
                    (scan.scan_id, host.address, index, json.dumps(asdict(finding))),
                )


def _scan_from_payload(payload: str) -> Scan:
    """Rebuild nested dataclasses from a serialized scan payload."""
    data: dict[str, Any] = json.loads(payload)
    hosts: list[Host] = []
    for host_data in data.pop("hosts", []):
        host_data["ports"] = [Port(**item) for item in host_data.get("ports", [])]
        host_data["findings"] = [Finding(**item) for item in host_data.get("findings", [])]
        hosts.append(Host(**host_data))
    return Scan(**data, hosts=hosts)


def get_scan(scan_id: str, database: str | Path = DEFAULT_DATABASE) -> Scan:
    """Load a full scan by identifier or raise ``KeyError``."""
    with _connect(database) as connection:
        row = connection.execute("SELECT payload FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
    if row is None:
        raise KeyError(f"Scan {scan_id!r} was not found.")
    return _scan_from_payload(row["payload"])


def list_scans(database: str | Path = DEFAULT_DATABASE) -> list[dict[str, Any]]:
    """Return scan history summaries, newest first."""
    with _connect(database) as connection:
        rows = connection.execute(
            """SELECT scan_id, started_at, finished_at, profile, targets, status,
            risk_score, risk_label, error FROM scans ORDER BY started_at DESC"""
        ).fetchall()
    results: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item["targets"] = json.loads(item["targets"])
        results.append(item)
    return results
