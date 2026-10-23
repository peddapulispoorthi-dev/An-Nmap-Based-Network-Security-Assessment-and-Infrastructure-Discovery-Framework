"""Safe subprocess integration with the Nmap executable."""

import shutil
import subprocess
from pathlib import Path


class NmapError(RuntimeError):
    """Raised when Nmap is unavailable or a scan command fails."""


def find_nmap() -> str:
    """Return the Nmap executable path or raise a readable error."""
    executable = shutil.which("nmap")
    if not executable:
        raise NmapError("Nmap was not found. Install Nmap and ensure it is available on PATH.")
    return executable


def run_nmap(
    targets: list[str],
    arguments: list[str],
    output_file: str | Path,
    timeout: int = 900,
) -> subprocess.CompletedProcess[str]:
    """Run Nmap with an argument list and save its XML output to a file."""
    if not targets or not all(targets):
        raise NmapError("Nmap requires at least one validated target.")
    executable = find_nmap()
    destination = Path(output_file)
    destination.parent.mkdir(parents=True, exist_ok=True)
    command = [executable, *arguments, "-oX", str(destination), *targets]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise NmapError(f"Nmap scan timed out after {timeout} seconds.") from exc
    except OSError as exc:
        raise NmapError(f"Unable to start Nmap: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.strip() or f"Nmap exited with status {result.returncode}."
        raise NmapError(detail)
    if not destination.is_file():
        raise NmapError("Nmap completed without producing the requested XML output.")
    return result
