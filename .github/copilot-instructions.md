# Project rules

- Only support authorized network assessment; require explicit user permission
  before every scan.
- Never use shell command construction or `shell=True` for Nmap.
- Do not add exploitation, denial-of-service, or attack-payload functionality.
- Validate target syntax and reject CIDR ranges broader than `/16` by default.
- Preserve type hints, tests, clear errors, and audit logging.
