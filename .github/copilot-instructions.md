# Project rules

- Target Python 3.8+ and use only the Python standard library.
- Require `--i-have-permission` before running any scan; validate target syntax
  and bound CIDR scope unless the user explicitly adds `--allow-large`.
- Never construct shell commands or use `shell=True` for Nmap.
- Keep scans assessment-only: no exploitation, denial-of-service, or attack
  payloads.
- Preserve timestamped audit logging, raw XML, escaped HTML reports, and tests.
