"""Built-in scan profiles and default paths."""

from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCAN_DIR = PROJECT_ROOT / "scans"
DEFAULT_AUDIT_LOG = PROJECT_ROOT / "logs" / "audit.log"
DEFAULT_DATABASE = PROJECT_ROOT / "scans" / "history.sqlite3"


@dataclass(frozen=True)
class ScanProfile:
    """Declarative set of phases and port-scan options."""

    name: str
    discovery: bool
    port_selection: str
    service_detection: bool = False
    os_detection: bool = False
    vulnerability_scripts: bool = False
    traceroute: bool = False
    udp: bool = False


PROFILES = {
    "quick": ScanProfile("quick", discovery=True, port_selection="--top-ports 100"),
    "standard": ScanProfile(
        "standard",
        discovery=True,
        port_selection="--top-ports 1000",
        service_detection=True,
        os_detection=True,
    ),
    "full": ScanProfile(
        "full",
        discovery=True,
        port_selection="-p-",
        service_detection=True,
        os_detection=True,
        vulnerability_scripts=True,
        traceroute=True,
        udp=True,
    ),
}


def get_profile(name: str) -> ScanProfile:
    """Return a named scan profile or raise a clear validation error."""
    try:
        return PROFILES[name]
    except KeyError:
        raise ValueError(f"Unknown scan profile {name!r}; choose quick, standard, or full.") from None
