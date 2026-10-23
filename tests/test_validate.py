import pytest

from nmapfw.validate import ValidationError, require_permission, validate_target, validate_targets


@pytest.mark.parametrize(
    "target",
    ["192.0.2.12", "2001:db8::1", "scanner.example.org", "192.0.2.0/24", "2001:db8::/120"],
)
def test_valid_targets(target):
    assert validate_target(target)


@pytest.mark.parametrize(
    "target",
    ["", "not a target", "-sn", "192.0.2.1; whoami", "192.0.2.0/8", "2001:db8::/32"],
)
def test_invalid_or_broad_targets(target):
    with pytest.raises(ValidationError):
        validate_target(target)


def test_allow_large_and_multiple_targets():
    assert validate_target("192.0.0.0/8", allow_large=True) == "192.0.0.0/8"
    assert validate_targets("192.0.2.1, scanner.example.org") == [
        "192.0.2.1",
        "scanner.example.org",
    ]


def test_permission_required():
    with pytest.raises(ValidationError, match="Scan refused"):
        require_permission(False)
    require_permission(True)
