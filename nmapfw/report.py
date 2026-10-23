"""Generate point-in-time JSON, CSV, Markdown, and HTML reports."""

import csv
import html
import io
import json
from dataclasses import asdict
from pathlib import Path

from nmapfw.config import DEFAULT_SCAN_DIR
from nmapfw.models import Scan
from nmapfw.topology import topology_data

FORMATS = ("json", "csv", "md", "html")
SNAPSHOT_NOTE = (
    "This report is a point-in-time snapshot. Network state and service exposure can change."
)


def report_data(scan: Scan) -> dict[str, object]:
    """Return a JSON-safe report structure with scan metadata and hosts."""
    data = asdict(scan)
    data["snapshot_note"] = SNAPSHOT_NOTE
    data["topology"] = topology_data(scan)
    return data


def render_json(scan: Scan) -> str:
    """Render the scan as formatted JSON."""
    return json.dumps(report_data(scan), indent=2, sort_keys=True)


def render_csv(scan: Scan) -> str:
    """Render one CSV row per host and port (or one row for an empty host)."""
    output = io.StringIO(newline="")
    columns = [
        "host",
        "hostnames",
        "port",
        "protocol",
        "state",
        "service",
        "product",
        "version",
        "risk_score",
        "risk_label",
        "findings",
    ]
    writer = csv.DictWriter(output, fieldnames=columns)
    writer.writeheader()
    for host in scan.hosts:
        ports = host.ports or [None]
        for port in ports:
            writer.writerow(
                {
                    "host": host.address,
                    "hostnames": ";".join(host.hostnames),
                    "port": port.number if port else "",
                    "protocol": port.protocol if port else "",
                    "state": port.state if port else "",
                    "service": port.service if port else "",
                    "product": port.product if port else "",
                    "version": port.version if port else "",
                    "risk_score": host.risk_score,
                    "risk_label": scan.risk_label,
                    "findings": "; ".join(item.title for item in host.findings),
                }
            )
    return output.getvalue()


def render_markdown(scan: Scan) -> str:
    """Render readable Markdown with host, port, risk, and finding details."""
    lines = [
        "# Network Assessment Report",
        "",
        f"- **Scan ID:** {scan.scan_id}",
        f"- **Profile:** {scan.profile}",
        f"- **Targets:** {', '.join(scan.targets)}",
        f"- **Started:** {scan.started_at}",
        f"- **Status:** {scan.status}",
        f"- **Network risk:** {scan.risk_score}/100 ({scan.risk_label})",
        "",
        f"> {SNAPSHOT_NOTE}",
    ]
    if scan.error:
        lines.extend(["", f"**Scan errors:** {scan.error}"])
    for host in scan.hosts:
        lines.extend(
            [
                "",
                f"## Host {host.address}",
                "",
                f"- Status: {host.status}",
                f"- Hostnames: {', '.join(host.hostnames) or 'None'}",
                f"- Host risk: {host.risk_score}/100",
                "",
                "| Port | Protocol | State | Service | Product | Version |",
                "|---:|---|---|---|---|---|",
            ]
        )
        for port in host.ports:
            cells = (str(port.number), port.protocol, port.state, port.service, port.product, port.version)
            lines.append("| " + " | ".join(cell.replace("|", "\\|") for cell in cells) + " |")
        if host.findings:
            lines.extend(["", "### Findings"])
            for finding in host.findings:
                lines.extend(
                    [
                        f"- **{finding.severity.upper()}: {finding.title}** "
                        f"(port {finding.port if finding.port is not None else 'n/a'})",
                        f"  - {finding.description}",
                        f"  - Remediation: {finding.remediation}",
                    ]
                )
        if host.traceroute:
            path = " → ".join(str(hop.get("ip") or "unknown") for hop in host.traceroute)
            lines.extend(["", f"Traceroute: {path} → {host.address}"])
    return "\n".join(lines) + "\n"


def render_html(scan: Scan) -> str:
    """Render a complete HTML report with escaped dynamic content and inline CSS."""
    esc = lambda value: html.escape(str(value), quote=True)
    host_sections: list[str] = []
    for host in scan.hosts:
        rows = "".join(
            "<tr>"
            f"<td>{port.number}/{esc(port.protocol)}</td><td>{esc(port.state)}</td>"
            f"<td>{esc(port.service)}</td><td>{esc(port.product)}</td><td>{esc(port.version)}</td>"
            "</tr>"
            for port in host.ports
        ) or '<tr><td colspan="5">No port data</td></tr>'
        findings = "".join(
            f'<li class="{esc(finding.severity.lower())}">'
            f"<strong>{esc(finding.severity.upper())}: {esc(finding.title)}</strong> "
            f"{esc(finding.description)}<br><em>Fix: {esc(finding.remediation)}</em></li>"
            for finding in host.findings
        ) or "<li>No findings recorded.</li>"
        trace = " → ".join(
            esc(hop.get("hostname") or hop.get("ip") or "unknown") for hop in host.traceroute
        )
        host_sections.append(
            f"<section><h2>{esc(host.address)} <small>Risk {host.risk_score}/100</small></h2>"
            f"<p>Status: {esc(host.status)} | Names: {esc(', '.join(host.hostnames) or 'None')}</p>"
            "<table><thead><tr><th>Port</th><th>State</th><th>Service</th>"
            "<th>Product</th><th>Version</th></tr></thead>"
            f"<tbody>{rows}</tbody></table><h3>Findings</h3><ul>{findings}</ul>"
            f"<p>Traceroute: {trace or 'Not available'}</p></section>"
        )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Network Assessment {esc(scan.scan_id)}</title><style>
body{{font:16px system-ui,sans-serif;margin:2rem auto;max-width:1100px;padding:0 1rem;color:#18212f;background:#f4f7fb}}
header,section{{background:white;padding:1.25rem;margin:1rem 0;border-radius:12px;box-shadow:0 2px 10px #12203a12}}
.cards{{display:flex;gap:1rem;flex-wrap:wrap}}.card{{padding:1rem;background:#eef3fa;border-radius:8px}}
table{{width:100%;border-collapse:collapse}}th,td{{padding:.55rem;text-align:left;border-bottom:1px solid #dce3ed}}
.critical,.high{{color:#a21d25}}.medium{{color:#855500}}.low{{color:#28633b}}
small{{font-size:.75em;color:#526176}}.note{{border-left:4px solid #3876c8;padding:.5rem 1rem}}
</style></head><body><header><h1>Network Assessment Report</h1>
<p>Scan {esc(scan.scan_id)} | Profile {esc(scan.profile)} | Targets {esc(', '.join(scan.targets))}</p>
<div class="cards"><div class="card">Hosts: {len(scan.hosts)}</div>
<div class="card">Network risk: {scan.risk_score}/100 ({esc(scan.risk_label)})</div>
<div class="card">Status: {esc(scan.status)}</div></div>
<p class="note">{esc(SNAPSHOT_NOTE)}</p></header>{''.join(host_sections)}</body></html>"""


def render_report(scan: Scan, output_format: str) -> str:
    """Render one report format by name."""
    renderers = {
        "json": render_json,
        "csv": render_csv,
        "md": render_markdown,
        "html": render_html,
    }
    try:
        renderer = renderers[output_format.lower()]
    except KeyError:
        raise ValueError(f"Unsupported report format {output_format!r}; choose {', '.join(FORMATS)}.") from None
    return renderer(scan)


def generate_reports(scan: Scan, base_directory: str | Path = DEFAULT_SCAN_DIR) -> Path:
    """Write all four report formats under ``<base>/<scan_id>/``."""
    destination = Path(base_directory) / scan.scan_id
    destination.mkdir(parents=True, exist_ok=True)
    for output_format in FORMATS:
        filename = "report.md" if output_format == "md" else f"report.{output_format}"
        (destination / filename).write_text(render_report(scan, output_format), encoding="utf-8")
    return destination
