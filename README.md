# Nmap Network Security Assessment Framework

A permission-gated Python CLI and local web dashboard for repeatable Nmap-based
network discovery and security assessment.

## Design decisions

- Nmap is invoked using an argument list (never through a shell), and its XML
  output is parsed locally with Python's standard library.
- Network scans require an explicit authorization acknowledgement. This tool
  performs assessment only; it does not exploit vulnerabilities or run
  denial-of-service tests.
- Scan history uses SQLite, and reports are generated as point-in-time snapshots.
- The dashboard binds to `127.0.0.1` by default.

## Development status

The framework is being implemented milestone by milestone. See the CLI help and
test suite for the available features.

## Legal and ethical use

Only scan systems and networks that you own or are explicitly authorized to
assess. You are responsible for complying with applicable laws and policies.
