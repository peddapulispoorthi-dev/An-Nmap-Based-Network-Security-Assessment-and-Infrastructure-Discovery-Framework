import pytest

from nmapfw.models import Host, Port, Scan
from nmapfw.storage import save_scan
from nmapfw.web.app import create_app


@pytest.fixture
def client(tmp_path):
    app = create_app(
        {
            "TESTING": True,
            "DATABASE": tmp_path / "history.sqlite3",
            "SCAN_DIR": tmp_path / "reports",
            "AUDIT_LOG": tmp_path / "audit.log",
        }
    )
    return app.test_client(), app


def _csrf(client):
    client.get("/")
    with client.session_transaction() as session:
        return session["csrf_token"]


def test_home_history_and_missing_results_routes(client):
    test_client, _app = client
    assert test_client.get("/").status_code == 200
    assert b"written permission" in test_client.get("/").data
    assert test_client.get("/history").status_code == 200
    assert test_client.get("/scans/missing").status_code == 404


def test_scan_post_requires_csrf_authorization_and_same_origin(client):
    test_client, _app = client
    token = _csrf(test_client)
    invalid_csrf = test_client.post(
        "/scan",
        data={"csrf_token": "wrong", "targets": "192.0.2.1", "authorized": "on"},
    )
    assert invalid_csrf.status_code == 400
    cross_origin = test_client.post(
        "/scan",
        data={"csrf_token": token, "targets": "192.0.2.1", "authorized": "on"},
        headers={"Origin": "https://evil.example"},
    )
    assert cross_origin.status_code == 403
    no_permission = test_client.post(
        "/scan",
        data={"csrf_token": token, "targets": "192.0.2.1"},
    )
    assert no_permission.status_code == 400


def test_background_scan_progress_results_host_download_and_busy_gate(tmp_path):
    def fake_scan(targets, profile, **kwargs):
        kwargs["progress_callback"]("ports", "completed")
        return Scan(
            targets,
            profile=profile,
            scan_id=kwargs["scan_id"],
            hosts=[Host(targets[0], status="up", ports=[Port(80, "tcp", "open", "http")])],
        )

    app = create_app(
        {
            "TESTING": True,
            "DATABASE": tmp_path / "history.sqlite3",
            "SCAN_DIR": tmp_path / "reports",
            "AUDIT_LOG": tmp_path / "audit.log",
        },
        scan_function=fake_scan,
    )
    client = app.test_client()
    token = _csrf(client)
    response = client.post(
        "/scan",
        data={
            "csrf_token": token,
            "targets": "192.0.2.10",
            "profile": "quick",
            "authorized": "on",
        },
    )
    assert response.status_code == 302
    scan_id = response.location.split("/")[2]
    state = app.extensions["nmapfw_scan_state"]
    state["thread"].join(timeout=3)
    assert state["status"] == "completed"
    assert client.get(f"/api/scan/{scan_id}").json["status"] == "completed"
    assert client.get(f"/scan/{scan_id}/progress").status_code == 200
    assert client.get(f"/scans/{scan_id}").status_code == 200
    assert client.get(f"/scans/{scan_id}/hosts/192.0.2.10").status_code == 200
    for output_format in ("json", "csv", "md", "html"):
        download = client.get(f"/scans/{scan_id}/report/{output_format}")
        assert download.status_code == 200
        assert download.data
    assert client.get("/history").status_code == 200
    assert client.get(f"/diff/{scan_id}/{scan_id}").status_code == 200


def test_scan_route_rejects_invalid_target(client):
    test_client, _app = client
    response = test_client.post(
        "/scan",
        data={
            "csrf_token": _csrf(test_client),
            "targets": "-sn",
            "authorized": "on",
        },
    )
    assert response.status_code == 400
    assert b"Invalid hostname" in response.data or b"Invalid IP" in response.data
