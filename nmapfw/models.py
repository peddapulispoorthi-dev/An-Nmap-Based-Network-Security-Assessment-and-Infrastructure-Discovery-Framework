"""Typed domain models for parsed and analyzed scans."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Port:
    """A network port and the service Nmap identified on it."""

    number: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    scripts: dict[str, str] = field(default_factory=dict)


@dataclass
class Finding:
    """A security observation with severity and remediation guidance."""

    title: str
    severity: str
    description: str
    remediation: str
    host: str = ""
    port: int | None = None
    cves: list[str] = field(default_factory=list)


@dataclass
class Host:
    """A discovered host and its scan results."""

    address: str
    status: str = "unknown"
    mac_address: str = ""
    vendor: str = ""
    hostnames: list[str] = field(default_factory=list)
    ports: list[Port] = field(default_factory=list)
    os_matches: list[dict[str, Any]] = field(default_factory=list)
    traceroute: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    risk_score: int = 0


@dataclass
class Scan:
    """A complete scan result and its metadata."""

    targets: list[str]
    profile: str = "quick"
    scan_id: str = ""
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: str = ""
    status: str = "completed"
    error: str = ""
    hosts: list[Host] = field(default_factory=list)
    risk_score: int = 0
    risk_label: str = "Low"
    command: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Assign a stable identifier when one was not provided."""
        if not self.scan_id:
            self.scan_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
