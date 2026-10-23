"""Permission-gated, loopback-first Flask dashboard."""

import hmac
import io
import logging
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, abort, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.utils import secure_filename

from nmapfw.config import DEFAULT_AUDIT_LOG, DEFAULT_DATABASE, DEFAULT_SCAN_DIR, get_profile
from nmapfw.diff import compare_scans
from nmapfw.models import Scan
from nmapfw.phases import run_scan
from nmapfw.report import FORMATS, generate_reports, render_report
from nmapfw.storage import get_scan, list_scans, save_scan
from nmapfw.validate import ValidationError, require_permission, validate_targets

LOGGER = logging.getLogger(__name__)


def _same_origin_request() -> bool:
    """Check a supplied Origin or Referer against this request's host."""
    expected = (request.scheme, request.host)
    origin = request.headers.get("Origin")
    referer = request.headers.get("Referer")
    supplied = origin or referer
    if not supplied:
        return True
    parsed = urlsplit(supplied)
    return (parsed.scheme, parsed.netloc) == expected


def create_app(
    test_config: dict[str, object] | None = None,
    *,
    scan_function=None,
) -> Flask:
    """Create a configured dashboard app and its isolated scan state."""
    app = Flask(__name__)
    app.secret_key = secrets.token_bytes(32)
    app.config.update(
        DATABASE=DEFAULT_DATABASE,
        SCAN_DIR=DEFAULT_SCAN_DIR,
        AUDIT_LOG=DEFAULT_AUDIT_LOG,
        MAX_CONTENT_LENGTH=16 * 1024,
    )
    if test_config:
        app.config.update(test_config)
    scan_callable = scan_function or run_scan
    state: dict[str, object] = {"status": "idle", "scan_id": "", "phase": "", "error": ""}
    state_lock = threading.Lock()
    app.extensions["nmapfw_scan_state"] = state
    app.extensions["nmapfw_scan_lock"] = state_lock

    @app.after_request
    def add_security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; "
            "base-uri 'self'; frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    def index():
        token = session.setdefault("csrf_token", secrets.token_urlsafe(32))
        with state_lock:
            current = dict(state)
        return render_template("index.html", csrf_token=token, scan=current)

    @app.post("/scan")
    def start_scan():
        if not _same_origin_request():
            abort(403, description="Cross-origin scan requests are not allowed.")
        token = session.get("csrf_token", "")
        supplied_token = request.form.get("csrf_token", "")
        if not token or not hmac.compare_digest(token, supplied_token):
            abort(400, description="Invalid or missing CSRF token.")
        try:
            require_permission(request.form.get("authorized") == "on")
            targets = validate_targets(request.form.get("targets", ""))
            profile = get_profile(request.form.get("profile", "quick")).name
        except (ValidationError, ValueError) as exc:
            token = session.setdefault("csrf_token", secrets.token_urlsafe(32))
            return render_template("index.html", csrf_token=token, scan=dict(state), error=str(exc)), 400

        scan_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        with state_lock:
            if state.get("status") == "running":
                return render_template(
                    "index.html",
                    csrf_token=token,
                    scan=dict(state),
                    error="A scan is already running. Wait for it to finish before starting another.",
                ), 409
            state.update(status="running", scan_id=scan_id, phase="queued", error="")

            def update_progress(phase: str, status: str) -> None:
                with state_lock:
                    state.update(phase=f"{phase}: {status}")

            def work() -> None:
                try:
                    scan = scan_callable(
                        targets,
                        profile,
                        permission=True,
                        output_dir=Path(app.config["SCAN_DIR"]) / scan_id,
                        database=app.config["DATABASE"],
                        audit_log=app.config["AUDIT_LOG"],
                        scan_id=scan_id,
                        progress_callback=update_progress,
                    )
                    save_scan(scan, app.config["DATABASE"])
                    generate_reports(scan, app.config["SCAN_DIR"])
                    with state_lock:
                        state.update(status=scan.status, phase="complete", scan_id=scan.scan_id)
                except Exception as exc:
                    LOGGER.exception("Background assessment %s failed", scan_id)
                    with state_lock:
                        state.update(status="failed", phase="failed", error=str(exc))

            thread = threading.Thread(target=work, name=f"nmapfw-{scan_id}", daemon=True)
            state["thread"] = thread
            thread.start()
        return redirect(url_for("scan_progress", scan_id=scan_id))

    @app.get("/scan/<scan_id>/progress")
    def scan_progress(scan_id: str):
        with state_lock:
            if state.get("scan_id") != scan_id:
                abort(404)
            current = dict(state)
        return render_template("scan.html", scan=current)

    @app.get("/api/scan/<scan_id>")
    def scan_status(scan_id: str):
        with state_lock:
            if state.get("scan_id") != scan_id:
                abort(404)
            current = dict(state)
        current.pop("thread", None)
        return jsonify(current)

    @app.get("/scans/<scan_id>")
    def scan_results(scan_id: str):
        try:
            scan = get_scan(scan_id, app.config["DATABASE"])
        except KeyError:
            abort(404)
        return render_template(
            "results.html",
            scan=scan,
            formats=FORMATS,
            topology=scan_topology(scan),
        )

    @app.get("/scans/<scan_id>/hosts/<path:address>")
    def host_detail(scan_id: str, address: str):
        try:
            scan = get_scan(scan_id, app.config["DATABASE"])
        except KeyError:
            abort(404)
        host = next((item for item in scan.hosts if item.address == address), None)
        if host is None:
            abort(404)
        return render_template("host.html", scan=scan, host=host)

    @app.get("/history")
    def history():
        return render_template("history.html", scans=list_scans(app.config["DATABASE"]))

    @app.get("/diff/<id_a>/<id_b>")
    def diff_view(id_a: str, id_b: str):
        try:
            older = get_scan(id_a, app.config["DATABASE"])
            newer = get_scan(id_b, app.config["DATABASE"])
        except KeyError:
            abort(404)
        return render_template(
            "diff.html",
            older=older,
            newer=newer,
            changes=compare_scans(older, newer),
        )

    @app.get("/scans/<scan_id>/report/<output_format>")
    def download_report(scan_id: str, output_format: str):
        if output_format not in FORMATS:
            abort(404)
        try:
            scan = get_scan(scan_id, app.config["DATABASE"])
        except KeyError:
            abort(404)
        content = render_report(scan, output_format)
        extensions = {"md": "md", "json": "json", "csv": "csv", "html": "html"}
        mimetypes = {
            "md": "text/markdown",
            "json": "application/json",
            "csv": "text/csv",
            "html": "text/html",
        }
        filename = secure_filename(f"report-{scan.scan_id}.{extensions[output_format]}")
        return send_file(
            io.BytesIO(content.encode("utf-8")),
            mimetype=mimetypes[output_format],
            as_attachment=True,
            download_name=filename,
        )

    return app


def scan_topology(scan: Scan) -> dict[str, list[dict[str, str | int]]]:
    """Return topology for templates without exposing implementation details."""
    from nmapfw.topology import topology_data

    return topology_data(scan)


def main() -> None:
    """Run the dashboard on the local loopback interface."""
    create_app().run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
