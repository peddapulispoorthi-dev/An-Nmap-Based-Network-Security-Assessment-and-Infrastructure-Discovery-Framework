"""Input validation and explicit authorization checks."""

import ipaddress
import re


class ValidationError(ValueError):
    """Raised when a target or authorization acknowledgement is invalid."""


_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def validate_target(target: str, allow_large: bool = False) -> str:
    """Validate and return one IPv4, IPv6, hostname, or CIDR target."""
    value = target.strip()
    if not value or any(char in value for char in "\r\n\t ,;"):
        raise ValidationError("Target must be a single IP address, hostname, or CIDR.")
    try:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=False)
            if not allow_large:
                minimum_prefix = 16 if network.version == 4 else 112
                if network.prefixlen < minimum_prefix:
                    raise ValidationError(
                        f"CIDR range {value!r} is too large; use /{minimum_prefix} or narrower, "
                        "or explicitly allow large networks."
                    )
            return str(network)
        return str(ipaddress.ip_address(value))
    except ValueError:
        if "/" in value or ":" in value:
            raise ValidationError(f"Invalid IP address or CIDR target: {value!r}") from None
    hostname = value.rstrip(".")
    if len(hostname) > 253 or not hostname:
        raise ValidationError("Hostname must be between 1 and 253 characters.")
    labels = hostname.split(".")
    if not all(_HOST_LABEL.fullmatch(label) for label in labels):
        raise ValidationError(f"Invalid hostname target: {value!r}")
    return hostname.lower()


def validate_targets(targets: str | list[str], allow_large: bool = False) -> list[str]:
    """Validate comma/space-separated targets or a list of individual targets."""
    candidates = targets if isinstance(targets, list) else re.split(r"[,\s]+", targets.strip())
    if not candidates or any(not str(item).strip() for item in candidates):
        raise ValidationError("At least one non-empty target is required.")
    return list(dict.fromkeys(validate_target(str(item), allow_large) for item in candidates))


def require_permission(acknowledged: bool) -> None:
    """Require explicit confirmation that the user is authorized to scan."""
    if not acknowledged:
        raise ValidationError(
            "Scan refused: confirm that you own or have written permission to assess the target."
        )
