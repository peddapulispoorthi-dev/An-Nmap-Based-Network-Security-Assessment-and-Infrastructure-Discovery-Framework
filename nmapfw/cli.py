"""Command-line interface for authorized network assessment."""

import argparse
import json
import sqlite3
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from nmapfw.config import DEFAULT_DATABASE, DEFAULT_SCAN_DIR
from nmapfw.diff import compare_scans
from nmapfw.models import Scan
from nmapfw.phases import run_scan
from nmapfw.report import FORMATS, generate_reports, render_report
from nmapfw.runner import NmapError
from nmapfw.storage import get_scan, list_scans
from nmapfw.validate import ValidationError


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nmapfw",
        description="Permission-gated Nmap network discovery and security assessment.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="Run an authorized Nmap scan profile.")
    scan.add_argument("targets", help="IP address, hostname, CIDR, or comma/space-separated targets.")
    scan.add_argument("--profile", choices=("quick", "standard", "full"), default="quick")
    scan.add_argument(
        "--i-have-permission",
        action="store_true",
        required=True,
        help="Confirm that you own or have written permission to assess these targets.",
    )
    scan.add_argument("--allow-large", action="store_true", help="Allow CIDR ranges broader than /16.")
    scan.add_argument("--vuln", action="store_true", help="Run Nmap's vuln NSE checks.")
    scan.add_argument("--udp", action="store_true", help="Add a top-50 UDP scan.")
    scan.add_argument("--out", type=Path, default=DEFAULT_SCAN_DIR, help="Report/output root directory.")

    history = commands.add_parser("history", help="List saved scans.")
    history.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    show = commands.add_parser("show", help="Show a saved scan.")
    show.add_argument("scan_id")
    show.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    diff = commands.add_parser("diff", help="Compare two saved scans.")
    diff.add_argument("id_a")
    diff.add_argument("id_b")
    diff.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    report = commands.add_parser("report", help="Render a saved scan report.")
    report.add_argument("scan_id")
    report.add_argument("--format", choices=FORMATS, default="html")
    report.add_argument("--out", type=Path)
    report.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
    return parser


def _print_scan_summary(scan: Scan) -> None:
    print(f"Scan {scan.scan_id}: {scan.status} | profile={scan.profile}")
    print(f"Targets: {', '.join(scan.targets)}")
    print(f"Hosts: {len(scan.hosts)} | Risk: {scan.risk_score}/100 ({scan.risk_label})")
    print("HOST                 STATUS  OPEN PORTS  RISK")
    print("-------------------- ------- ----------- ----")
    for host in scan.hosts:
        open_ports = ", ".join(str(port.number) for port in host.ports if port.state == "open") or "-"
        print(f"{host.address:<20} {host.status:<7} {open_ports:<11} {host.risk_score:>3}")
    if scan.error:
        print(f"Errors: {scan.error}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    """Run a CLI command and return its process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            scan_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            output_root = args.out
            scan = run_scan(
                args.targets,
                args.profile,
                permission=args.i_have_permission,
                allow_large=args.allow_large,
                include_vuln=args.vuln,
                include_udp=args.udp,
                output_dir=output_root / scan_id,
                scan_id=scan_id,
                progress_callback=lambda phase, state: print(f"[{phase}] {state}", flush=True),
            )
            report_directory = generate_reports(scan, output_root)
            _print_scan_summary(scan)
            print(f"Reports: {report_directory}")
            return 1 if scan.status == "failed" else 0
        if args.command == "history":
            scans = list_scans(args.database)
            if not scans:
                print("No saved scans.")
                return 0
            for item in scans:
                print(
                    f"{item['scan_id']}  {item['profile']:<8} {item['status']:<8} "
                    f"risk={item['risk_score']:>3} {', '.join(item['targets'])}"
                )
            return 0
        if args.command == "show":
            print(json.dumps(asdict(get_scan(args.scan_id, args.database)), indent=2))
            return 0
        if args.command == "diff":
            changes = compare_scans(
                get_scan(args.id_a, args.database),
                get_scan(args.id_b, args.database),
            )
            print(json.dumps(changes, indent=2))
            return 0
        if args.command == "report":
            scan = get_scan(args.scan_id, args.database)
            content = render_report(scan, args.format)
            if args.out:
                args.out.parent.mkdir(parents=True, exist_ok=True)
                args.out.write_text(content, encoding="utf-8")
                print(f"Report written to {args.out}")
            else:
                sys.stdout.write(content)
            return 0
    except (ValidationError, NmapError, ValueError, OSError, KeyError, sqlite3.Error) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    return 2
