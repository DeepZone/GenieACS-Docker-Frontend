import json
import os
import socket
import time
from threading import Lock, Thread
from uuid import uuid4
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from ipaddress import ip_address
from urllib.parse import quote, urlparse

import requests
from flask import Flask, flash, jsonify, redirect, render_template, request, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-me-in-production")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:////data/app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

os.makedirs("/data", exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
ONLINE_WINDOW_MINUTES = 15
UTC = timezone.utc

DASHBOARD_PROJECTION_FIELDS = [
    "_id",
    "_lastInform",
    "InternetGatewayDevice.WANDevice",
]

DEVICES_PROJECTION_FIELDS = [
    "_id",
    "_lastInform",
    "DeviceID.Manufacturer",
    "DeviceID.ProductClass",
    "InternetGatewayDevice.DeviceInfo.X_AVM-DE_ProdSerialNumber",
    "InternetGatewayDevice.DeviceInfo.ModelName",
]

DEVICE_DETAIL_PROJECTION_FIELDS = [
    "_id",
    "_lastInform",
    "DeviceID.Manufacturer",
    "DeviceID.ProductClass",
    "InternetGatewayDevice.DeviceInfo.X_AVM-DE_ProdSerialNumber",
    "InternetGatewayDevice.DeviceInfo.ModelName",
    "InternetGatewayDevice.WANDevice",
    "InternetGatewayDevice.LANDevice",
    "InternetGatewayDevice.X_AVM-DE_DiagnosticTools.IPLayerCapacity",
]

UDPST_STATUS_PARAMETER_NAMES = [
    "InternetGatewayDevice.X_AVM-DE_DiagnosticTools.IPLayerCapacity.Control.State",
    "InternetGatewayDevice.X_AVM-DE_DiagnosticTools.IPLayerCapacity.Result.Success",
    "InternetGatewayDevice.X_AVM-DE_DiagnosticTools.IPLayerCapacity.Result.Message",
    "InternetGatewayDevice.X_AVM-DE_DiagnosticTools.IPLayerCapacity.Result.Result",
    "InternetGatewayDevice.X_AVM-DE_DiagnosticTools.IPLayerCapacity.Config.TestIntervalSecs",
]

UDPST_TEST_PORT = int(os.getenv("UDPST_TEST_PORT", "25000"))
UDPST_TEST_ROLE = os.getenv("UDPST_TEST_ROLE", "Receiver")
UDPST_HEALTHCHECK_TIMEOUT_SECONDS = float(os.getenv("UDPST_HEALTHCHECK_TIMEOUT_SECONDS", "1.5"))
UDPST_DEBUG_MAX_ENTRIES = int(os.getenv("UDPST_DEBUG_MAX_ENTRIES", "120"))
UDPST_RUNNING_STATE = "running"
UDPST_DEBUG_TRACES: dict[str, list[dict[str, str]]] = {}
UDPST_DEBUG_LOCK = Lock()
UDPST_RUN_CONTEXTS: dict[str, dict[str, object]] = {}
UDPST_RUN_CONTEXT_LOCK = Lock()
UDPST_AJAX_JOBS: dict[str, dict[str, object]] = {}
UDPST_AJAX_DEVICE_JOBS: dict[str, str] = {}
UDPST_AJAX_LOCK = Lock()

IDENTITY_FIELDS = ("manufacturer", "product_class", "serial_number", "model")

IDENTITY_VALUE_PATHS: dict[str, list[str]] = {
    "manufacturer": ["DeviceID", "Manufacturer"],
    "product_class": ["DeviceID", "ProductClass"],
    "serial_number": ["InternetGatewayDevice", "DeviceInfo", "X_AVM-DE_ProdSerialNumber"],
    "model": ["InternetGatewayDevice", "DeviceInfo", "ModelName"],
}

IDENTITY_PARAMETER_NAMES = [
    "DeviceID.Manufacturer",
    "DeviceID.ProductClass",
    "InternetGatewayDevice.DeviceInfo.X_AVM-DE_ProdSerialNumber",
    "InternetGatewayDevice.DeviceInfo.ModelName",
]


@app.template_filter("bytes_to_human")
def bytes_to_human(value: int | None) -> str:
    if value is None:
        return "0 B"
    suffixes = ["B", "KB", "MB", "GB", "TB", "PB"]
    size = float(value)
    for suffix in suffixes:
        if size < 1024 or suffix == suffixes[-1]:
            return f"{size:.2f} {suffix}"
        size /= 1024
    return "0 B"


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(40), nullable=False, default="viewer")
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(UTC))

    def set_password(self, raw_password: str) -> None:
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password_hash(self.password_hash, raw_password)


class AppConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    acs_api_url = db.Column(db.String(500), nullable=False, default="http://genieacs:7557")
    udpst_server_url = db.Column(db.String(500), nullable=False, default="")
    udpst_server_port = db.Column(db.Integer, nullable=False, default=UDPST_TEST_PORT)
    updated_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(UTC))


@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))


@app.before_request
def ensure_setup_complete():
    if request.endpoint in {"static"}:
        return None

    user_count = User.query.count()
    setup_allowed_endpoints = {"initial_setup", "login", "logout"}

    if user_count == 0 and request.endpoint not in setup_allowed_endpoints:
        return redirect(url_for("initial_setup"))

    if user_count > 0 and request.endpoint == "initial_setup":
        return redirect(url_for("login"))

    return None


@app.route("/")
def root():
    if User.query.count() == 0:
        return redirect(url_for("initial_setup"))
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/setup", methods=["GET", "POST"])
def initial_setup():
    if User.query.count() > 0:
        return redirect(url_for("login"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        acs_api_url = request.form.get("acs_api_url", "").strip()

        if not username or not password or not acs_api_url:
            flash("Bitte alle Felder ausfüllen.", "danger")
            return render_template("setup.html")

        admin = User(username=username, role="admin")
        admin.set_password(password)

        config = AppConfig(
            acs_api_url=acs_api_url,
            udpst_server_url="",
            udpst_server_port=UDPST_TEST_PORT,
            updated_at=datetime.now(UTC),
        )

        db.session.add(admin)
        db.session.add(config)
        db.session.commit()

        flash("Admin-Benutzer wurde angelegt. Bitte einloggen.", "success")
        return redirect(url_for("login"))

    return render_template("setup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for("dashboard"))

        flash("Ungültige Zugangsdaten.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Du wurdest ausgeloggt.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    config = AppConfig.query.first()
    summary = None
    dashboard_error = None
    udpst_server_status = get_udpst_server_status(config)

    if config and config.acs_api_url:
        try:
            summary = load_dashboard_summary(config.acs_api_url.rstrip("/"))
        except requests.RequestException:
            dashboard_error = "ACS-API ist derzeit nicht erreichbar."
        except ValueError:
            dashboard_error = "ACS-Antwort konnte nicht verarbeitet werden."
    else:
        dashboard_error = "Keine ACS-API-URL konfiguriert."

    return render_template(
        "dashboard.html",
        config=config,
        summary=summary,
        dashboard_error=dashboard_error,
        udpst_server_status=udpst_server_status,
    )


@app.route("/devices")
@login_required
def devices():
    config = AppConfig.query.first()
    status_filter = request.args.get("status", "all").strip().lower()
    if status_filter not in {"all", "online", "offline"}:
        status_filter = "all"

    device_rows: list[dict] = []
    devices_error = None

    if config and config.acs_api_url:
        try:
            device_rows = load_devices(config.acs_api_url.rstrip("/"), status_filter)
        except requests.RequestException:
            devices_error = "ACS-API ist derzeit nicht erreichbar."
        except ValueError:
            devices_error = "ACS-Antwort konnte nicht verarbeitet werden."
    else:
        devices_error = "Keine ACS-API-URL konfiguriert."

    return render_template(
        "devices.html",
        config=config,
        devices=device_rows,
        status_filter=status_filter,
        devices_error=devices_error,
        online_window_minutes=ONLINE_WINDOW_MINUTES,
    )


@app.route("/devices/<device_id>")
@login_required
def device_detail(device_id: str):
    config = AppConfig.query.first()
    detail_error = None
    device = None
    udpst_server_status = get_udpst_server_status(config)
    if config and config.acs_api_url:
        try:
            device = load_device_detail(config.acs_api_url.rstrip("/"), device_id)
            if device is None:
                detail_error = "Gerät wurde im ACS nicht gefunden."
        except requests.RequestException:
            detail_error = "ACS-API ist derzeit nicht erreichbar."
        except ValueError:
            detail_error = "ACS-Antwort konnte nicht verarbeitet werden."
    else:
        detail_error = "Keine ACS-API-URL konfiguriert."

    run_context = get_udpst_run_context(device_id)
    run_status = str(run_context.get("status") or "")
    active_run_statuses = {"pending", "trigger_sent", "device_run_detected"}
    control_state = str((device or {}).get("udpst", {}).get("control_state", "")).strip().lower() if device else ""
    is_running = bool(control_state == UDPST_RUNNING_STATE)
    return render_template(
        "device_detail.html",
        config=config,
        device=device,
        detail_error=detail_error,
        online_window_minutes=ONLINE_WINDOW_MINUTES,
        udpst_server_status=udpst_server_status,
        udpst_debug_trace=get_udpst_debug_trace(device_id),
        udpst_running=bool(is_running or run_status in active_run_statuses),
    )


@app.post("/api/devices/<device_id>/udpst/jobs")
@login_required
def start_udpst_ajax_job(device_id: str):
    config = AppConfig.query.first()
    if not config or not config.acs_api_url:
        return jsonify({"ok": False, "error": "Keine ACS-API-URL konfiguriert."}), 400

    payload = request.get_json(silent=True) or {}
    selected_role = str(payload.get("role", "Receiver")).strip()
    if selected_role not in {"Receiver", "Sender"}:
        return jsonify({"ok": False, "error": "Ungültige Rolle. Erlaubt: Receiver oder Sender."}), 400

    with UDPST_AJAX_LOCK:
        existing_job_id = UDPST_AJAX_DEVICE_JOBS.get(device_id)
        if existing_job_id:
            existing_job = UDPST_AJAX_JOBS.get(existing_job_id, {})
            if existing_job and str(existing_job.get("state")) in {"queued", "running"}:
                return jsonify({"ok": False, "error": "Für dieses Gerät läuft bereits ein UDPST-Job.", "job_id": existing_job_id}), 409

    job_id = uuid4().hex
    started_at = datetime.now(UTC).isoformat(timespec="seconds")
    job_data = {
        "job_id": job_id,
        "device_id": device_id,
        "state": "queued",
        "phase": 1,
        "status_text": "Aktuelle ACS-Konfiguration wird gelesen",
        "progress": 5,
        "selected_role": selected_role,
        "error": "",
        "result_message": "",
        "result_result": "",
        "test_interval_secs": None,
        "wait_seconds": 0,
        "wait_remaining": 0,
        "acs_snapshot": {},
        "device_udpst": None,
        "updated_at": started_at,
    }
    with UDPST_AJAX_LOCK:
        UDPST_AJAX_JOBS[job_id] = job_data
        UDPST_AJAX_DEVICE_JOBS[device_id] = job_id

    monitor_target = resolve_udpst_monitor_target(config)
    worker = Thread(
        target=run_udpst_ajax_job,
        args=(config.acs_api_url.rstrip("/"), device_id, job_id, selected_role, monitor_target),
        daemon=True,
    )
    worker.start()
    return jsonify({"ok": True, "job_id": job_id, "state": "queued"})


@app.get("/api/devices/<device_id>/udpst/jobs/<job_id>")
@login_required
def get_udpst_ajax_job_status(device_id: str, job_id: str):
    with UDPST_AJAX_LOCK:
        job = dict(UDPST_AJAX_JOBS.get(job_id, {}))
    if not job or str(job.get("device_id")) != device_id:
        return jsonify({"ok": False, "error": "Job nicht gefunden."}), 404
    return jsonify({"ok": True, "job": job})


@app.post("/devices/<device_id>/udpst")
@login_required
def device_udpst_action(device_id: str):
    config = AppConfig.query.first()
    if not config or not config.acs_api_url:
        flash("Keine ACS-API-URL konfiguriert.", "danger")
        return redirect(url_for("device_detail", device_id=device_id))

    action = request.form.get("action", "").strip()
    acs_api_url = config.acs_api_url.rstrip("/")
    append_udpst_debug_trace(
        device_id,
        "request",
        f"POST /devices/{device_id}/udpst empfangen, action='{action or '-'}'",
    )

    try:
        if action == "run_udpst_test":
            clear_udpst_debug_trace(device_id)
            run_started_at = datetime.now(UTC).replace(microsecond=0)
            set_udpst_run_context(
                device_id,
                {
                    "status": "pending",
                    "start_time_iso": run_started_at.isoformat(),
                    "trigger_sent": False,
                    "device_run_detected": False,
                    "completion_detected": False,
                    "stale_detected": False,
                    "stale_warning": "",
                },
            )
            append_udpst_debug_trace(
                device_id,
                "request",
                f"POST /devices/{device_id}/udpst empfangen, action='run_udpst_test'",
            )
            append_udpst_debug_trace(device_id, "run", f"Startzeitpunkt des Requests (UTC): {run_started_at.isoformat()}")
            append_udpst_debug_trace(device_id, "action", "UDPST-Test gestartet (UI)")
            monitor_target = resolve_udpst_monitor_target(config)
            host = monitor_target.get("host", "")
            port = monitor_target.get("port")
            role = UDPST_TEST_ROLE.strip()
            append_udpst_debug_trace(
                device_id,
                "config",
                f"Verwende Host={host or '-'} Port={port if port is not None else '-'} Role={role or '-'}",
            )

            if not host or port is None:
                update_udpst_run_context(device_id, status="start_failed", stale_warning="Start abgebrochen: Host oder Port fehlt.")
                flash(
                    "UDPST-Start fehlgeschlagen: UDPST-Serveradresse ist nicht vollständig konfiguriert (Host/Port).",
                    "warning",
                )
                append_udpst_debug_trace(device_id, "validation", "Abbruch: Host oder Port fehlt")
                return redirect(url_for("device_detail", device_id=device_id))
            if role not in {"Receiver", "Sender"}:
                append_udpst_debug_trace(
                    device_id, "validation", f"Ungültige Role '{role}' erkannt, fallback auf Receiver"
                )
                role = "Receiver"

            queue_set_parameter_values_task(
                acs_api_url,
                device_id,
                [
                    ("InternetGatewayDevice.X_AVM-DE_DiagnosticTools.IPLayerCapacity.Config.Host", host, "xsd:string"),
                    ("InternetGatewayDevice.X_AVM-DE_DiagnosticTools.IPLayerCapacity.Config.Port", port, "xsd:unsignedInt"),
                    ("InternetGatewayDevice.X_AVM-DE_DiagnosticTools.IPLayerCapacity.Config.Role", role, "xsd:string"),
                    ("InternetGatewayDevice.X_AVM-DE_DiagnosticTools.IPLayerCapacity.Control.Start", True, "xsd:boolean"),
                ],
            )
            append_udpst_debug_trace(
                device_id,
                "state",
                "Control.Start=true wurde per setParameterValues an ACS gesendet (kombiniert mit Config.*).",
            )
            queue_connection_request_task(acs_api_url, device_id)
            append_udpst_debug_trace(
                device_id,
                "state",
                "Zusätzlicher connection_request Task wurde angelegt, damit das CPE den Start zeitnah ausführt.",
            )
            update_udpst_run_context(device_id, status="trigger_sent", trigger_sent=True)
            append_udpst_debug_trace(device_id, "state", "ACS-Task für Config.* + Control.Start wurde abgeschickt")
            current_device = load_device_detail(acs_api_url, device_id)
            if current_device and isinstance(current_device.get("udpst"), dict):
                udpst_snapshot = current_device["udpst"]
                append_udpst_debug_trace(
                    device_id,
                    "start-path",
                    (
                        "Pfadprüfung vor Polling: "
                        f"IPLayerCapacity.Config.Host={udpst_snapshot.get('test_host') or '-'} "
                        f"Port={udpst_snapshot.get('test_port') or '-'} "
                        f"Role={udpst_snapshot.get('test_role') or '-'} "
                        f"Control.State={udpst_snapshot.get('control_state') or '-'} "
                        f"Result.Success={udpst_snapshot.get('result_success') or '-'} "
                        f"Result.Message={udpst_snapshot.get('result_message') or '-'}"
                    ),
                )
            test_interval_seconds, timeout_seconds, poll_interval_seconds = determine_udpst_polling(current_device)
            append_udpst_debug_trace(
                device_id,
                "state",
                f"Control.Start gesetzt, TestIntervalSecs={test_interval_seconds}s, Polling bis {timeout_seconds}s mit Intervall {poll_interval_seconds}s",
            )
            poll_result = poll_udpst_result(
                acs_api_url,
                device_id,
                timeout_seconds=timeout_seconds,
                poll_interval_seconds=poll_interval_seconds,
                start_time=run_started_at,
            )
            if poll_result.get("completed_with_fresh_result"):
                flash("Neuer UDPST-Testlauf erkannt und erfolgreich abgeschlossen.", "success")
            elif poll_result.get("not_started_no_running"):
                flash(
                    "Der Start-Trigger wurde gesendet, aber Control.State wechselte nicht auf running. Der Test wurde daher nicht gestartet.",
                    "warning",
                )
            elif poll_result.get("stale_result_detected"):
                flash(
                    "Es wurde kein neuer Testlauf erkannt. Das gelesene Ergebnis stammt offenbar von einem früheren Lauf.",
                    "warning",
                )
            elif poll_result.get("trigger_sent"):
                flash(
                    "Trigger an ACS gesendet. Es wurde aber noch kein neuer Testlauf auf dem Gerät bestätigt.",
                    "warning",
                )
            else:
                flash(
                    "UDPST-Trigger konnte nicht bestätigt werden. Bitte Debug-Trace und CPE-Status prüfen.",
                    "warning",
                )
        elif action == "abort_udpst_test":
            append_udpst_debug_trace(device_id, "action", "UDPST-Testabbruch angefordert (UI)")
            queue_set_parameter_values_task(
                acs_api_url,
                device_id,
                [
                    ("InternetGatewayDevice.X_AVM-DE_DiagnosticTools.IPLayerCapacity.Control.Abort", True, "xsd:boolean"),
                ],
            )
            append_udpst_debug_trace(device_id, "action", "UDPST-Testabbruch ausgelöst")
            flash("UDPST-Testabbruch wurde ausgelöst.", "info")
        elif action == "debug_udpst_refresh":
            append_udpst_debug_trace(device_id, "action", "Debug-Refresh manuell ausgelöst")
            queue_get_parameter_values_task(acs_api_url, device_id, UDPST_STATUS_PARAMETER_NAMES)
            poll_result = poll_udpst_result(acs_api_url, device_id, timeout_seconds=25, poll_interval_seconds=2)
            if poll_result.get("completed_with_fresh_result") or poll_result.get("result_observed"):
                flash("Debug-Abruf erfolgreich: UDPST-Parameter und Result.Result wurden erneut abgefragt.", "success")
            else:
                flash(
                    "Debug-Abruf gestartet: Gerät hat noch kein finales Result.Result geliefert. Rohdaten prüfen.",
                    "warning",
                )
        else:
            append_udpst_debug_trace(
                device_id, "validation", f"Unbekannte Aktion empfangen: '{action or '-'}'"
            )
            flash("Unbekannte UDPST-Aktion.", "warning")
    except requests.RequestException:
        append_udpst_debug_trace(device_id, "error", "ACS-API RequestException während UDPST-Aktion")
        update_udpst_run_context(device_id, status="error")
        flash("ACS-API ist derzeit nicht erreichbar.", "danger")
    except Exception as exc:
        append_udpst_debug_trace(device_id, "error", f"Unerwarteter Fehler: {exc}")
        update_udpst_run_context(device_id, status="error")
        flash(f"UDPST-Aktion fehlgeschlagen: {exc}", "danger")

    return redirect(url_for("device_detail", device_id=device_id))


def load_dashboard_summary(acs_api_url: str) -> dict:
    active_since = datetime.now(UTC).replace(microsecond=0)
    active_since = active_since.timestamp() - (24 * 60 * 60)
    query = quote(f'{{"_lastInform":{{"$gte":"{datetime.fromtimestamp(active_since, UTC).isoformat()}"}}}}')

    projection = quote(",".join(DASHBOARD_PROJECTION_FIELDS))
    url = f"{acs_api_url}/devices/?query={query}&projection={projection}"

    response = requests.get(url, timeout=10)
    response.raise_for_status()
    devices = response.json()
    if not isinstance(devices, list):
        raise ValueError("Unexpected ACS response")

    class_counts = {"Cable": 0, "DSL": 0, "Fiber": 0, "Unknown": 0}
    total_rx_bytes = Decimal(0)
    total_tx_bytes = Decimal(0)

    for device in devices:
        connection_class = classify_connection(device)
        class_counts[connection_class] += 1
        rx, tx = extract_traffic_bytes(device)
        total_rx_bytes += rx
        total_tx_bytes += tx

    return {
        "active_window_hours": 24,
        "active_count": len(devices),
        "class_counts": class_counts,
        "total_rx_bytes": int(total_rx_bytes),
        "total_tx_bytes": int(total_tx_bytes),
        "total_traffic_bytes": int(total_rx_bytes + total_tx_bytes),
    }


def load_devices(acs_api_url: str, status_filter: str) -> list[dict]:
    projection = quote(",".join(DEVICES_PROJECTION_FIELDS))
    url = f"{acs_api_url}/devices/?projection={projection}"

    response = requests.get(url, timeout=10)
    response.raise_for_status()
    devices = response.json()
    if not isinstance(devices, list):
        raise ValueError("Unexpected ACS response")

    now = datetime.now(UTC)
    rows = []
    for device in devices:
        if not isinstance(device, dict):
            continue
        last_inform = parse_acs_datetime(device.get("_lastInform"))
        is_online = bool(last_inform and now - last_inform <= timedelta(minutes=ONLINE_WINDOW_MINUTES))
        if status_filter == "online" and not is_online:
            continue
        if status_filter == "offline" and is_online:
            continue

        identity = get_device_identity_values(acs_api_url, device)

        rows.append(
            {
                "device_id": device.get("_id", "unbekannt"),
                "manufacturer": identity["manufacturer"],
                "product_class": identity["product_class"],
                "serial_number": identity["serial_number"],
                "model": identity["model"],
                "last_inform": last_inform,
                "is_online": is_online,
            }
        )

    rows.sort(
        key=lambda row: (
            not row["is_online"],
            row["last_inform"] is None,
            -(row["last_inform"].timestamp() if row["last_inform"] else 0),
        )
    )
    return rows


def load_device_detail(
    acs_api_url: str,
    device_id: str,
    monitor_target: dict[str, object] | None = None,
) -> dict | None:
    projection = quote(",".join(DEVICE_DETAIL_PROJECTION_FIELDS))
    query = quote(json.dumps({"_id": device_id}, separators=(",", ":")))
    url = f"{acs_api_url}/devices/?query={query}&projection={projection}"

    response = requests.get(url, timeout=10)
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, list):
        raise ValueError("Unexpected ACS response")
    if not payload:
        return None

    device = payload[0]
    if not isinstance(device, dict):
        raise ValueError("Unexpected ACS response")

    last_inform = parse_acs_datetime(device.get("_lastInform"))
    now = datetime.now(UTC)
    is_online = bool(last_inform and now - last_inform <= timedelta(minutes=ONLINE_WINDOW_MINUTES))
    rx, tx = extract_traffic_bytes(device)
    wan_info = extract_wan_info(device)
    wan_common_info = extract_wan_common_info(device)
    wan_dsl_info = extract_wan_dsl_info(device)
    wan_cable_info = extract_wan_cable_info(device)
    connection_class = classify_connection(device)
    wifi_radios = extract_wifi_radios(device)
    udpst_info = extract_udpst_info(device, monitor_target=monitor_target)

    wan_common_rows = build_info_rows(
        wan_common_info,
        [
            ("wan_access_type", "WANAccessType"),
            ("link_type", "LinkType"),
            ("connection_status", "Verbindungsstatus"),
            ("connection_type", "Verbindungstyp"),
            ("internet_link_type", "Internet-Linktyp"),
            ("physical_link_status", "Physical Link"),
            ("external_ip", "Externe IP"),
            ("default_gateway", "Gateway"),
            ("dns_servers", "DNS-Server"),
            ("nat_enabled", "NAT aktiv"),
            ("downstream_max_rate", "Max-Datenrate Downstream"),
            ("upstream_max_rate", "Max-Datenrate Upstream"),
        ],
    )
    wan_dsl_rows = build_info_rows(
        wan_dsl_info,
        [
            ("status", "DSL-Status"),
            ("standard_used", "Standard"),
            ("current_profile", "Profil"),
            ("link_encapsulation_used", "Encapsulation"),
            ("data_path", "DataPath"),
            ("downstream_current_rate", "Aktuelle Datenrate Downstream"),
            ("upstream_current_rate", "Aktuelle Datenrate Upstream"),
            ("downstream_max_rate", "DSL Max-Rate Downstream"),
            ("upstream_max_rate", "DSL Max-Rate Upstream"),
            ("downstream_noise_margin", "Noise Margin Downstream"),
            ("upstream_noise_margin", "Noise Margin Upstream"),
        ],
    )
    wan_cable_rows = build_info_rows(
        wan_cable_info,
        [
            ("wan_access_type", "WANAccessType"),
            ("physical_link_status", "Physical Link"),
            ("downstream_current_max_speed", "Current Max Speed Downstream"),
            ("upstream_current_max_speed", "Current Max Speed Upstream"),
            ("downstream_utilization", "Utilization Downstream"),
            ("upstream_utilization", "Utilization Upstream"),
            ("total_bytes_received", "Total Bytes Received"),
            ("total_bytes_sent", "Total Bytes Sent"),
        ],
    )
    legacy_rows = build_info_rows(
        wan_info,
        [
            ("connection_name", "Verbindungsname"),
            ("uptime_seconds", "Uptime (Sek.)"),
            ("downstream_current_rate", "Downstream aktuell"),
            ("upstream_current_rate", "Upstream aktuell"),
            ("downstream_max_rate", "Max Downstream"),
            ("upstream_max_rate", "Max Upstream"),
        ],
    )

    internet_sections: list[dict[str, object]] = []
    if wan_common_rows:
        internet_sections.append({"title": "WAN (gemeinsam)", "rows": wan_common_rows})
    if connection_class == "DSL" and wan_dsl_rows:
        internet_sections.append({"title": "DSL (spezifisch)", "rows": wan_dsl_rows})
    elif connection_class == "Cable" and wan_cable_rows:
        internet_sections.append({"title": "Cable (spezifisch)", "rows": wan_cable_rows})
    else:
        if wan_dsl_rows:
            internet_sections.append({"title": "DSL (spezifisch)", "rows": wan_dsl_rows})
        if wan_cable_rows:
            internet_sections.append({"title": "Cable (spezifisch)", "rows": wan_cable_rows})
    if legacy_rows:
        internet_sections.append({"title": "WAN (Kompatibilität)", "rows": legacy_rows})

    identity = get_device_identity_values(acs_api_url, device)

    return {
        "device_id": device.get("_id", "unbekannt"),
        "manufacturer": identity["manufacturer"],
        "product_class": identity["product_class"],
        "serial_number": identity["serial_number"],
        "model": identity["model"],
        "last_inform": last_inform,
        "is_online": is_online,
        "connection_class": connection_class,
        "total_rx_bytes": int(rx),
        "total_tx_bytes": int(tx),
        "internet_sections": internet_sections,
        "wifi_radios": wifi_radios,
        "udpst": udpst_info,
    }


def build_info_rows(info: dict[str, str], field_definitions: list[tuple[str, str]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for key, label in field_definitions:
        raw_value = info.get(key)
        if raw_value is None:
            continue
        value = str(raw_value).strip()
        if not value or value == "-":
            continue
        rows.append({"label": label, "value": value})
    return rows


def get_device_identity_values(acs_api_url: str, device: dict) -> dict[str, str]:
    identity = {field: get_nested_acs_value(device, IDENTITY_VALUE_PATHS[field]) for field in IDENTITY_FIELDS}

    if any(not value for value in identity.values()):
        refreshed_device = refresh_identity_from_device(acs_api_url, str(device.get("_id", "")))
        if refreshed_device:
            identity = {field: get_nested_acs_value(refreshed_device, IDENTITY_VALUE_PATHS[field]) for field in IDENTITY_FIELDS}

    return {field: (identity.get(field) or "-") for field in IDENTITY_FIELDS}


def refresh_identity_from_device(acs_api_url: str, device_id: str) -> dict | None:
    if not device_id:
        return None

    task_url = f"{acs_api_url}/devices/{quote(device_id, safe='')}/tasks?timeout=10000&connection_request"
    task_payload = {"name": "getParameterValues", "parameterNames": IDENTITY_PARAMETER_NAMES}

    try:
        task_response = requests.post(task_url, json=task_payload, timeout=10)
        task_response.raise_for_status()
    except requests.RequestException:
        return None

    query = quote(json.dumps({"_id": device_id}, separators=(",", ":")))
    projection = quote(",".join(DEVICE_DETAIL_PROJECTION_FIELDS))
    url = f"{acs_api_url}/devices/?query={query}&projection={projection}"

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.RequestException:
        return None

    payload = response.json()
    if isinstance(payload, list) and payload and isinstance(payload[0], dict):
        return payload[0]

    return None


def get_nested_acs_value(device: dict, path: list[str]) -> str | None:
    node = resolve_acs_path_node(device, path)
    if node is None:
        return None

    if isinstance(node, dict):
        if "_value" in node and node["_value"] is not None:
            value = str(node["_value"]).strip()
            return value or None
        return None

    value = str(node).strip()
    return value or None


def resolve_acs_path_node(device: dict, path: list[str]) -> object | None:
    node: object = device
    for segment in path:
        if not isinstance(node, dict) or segment not in node:
            node = None
            break
        node = node[segment]
    if node is not None:
        return node

    if not isinstance(device, dict):
        return None

    full_key = ".".join(path)
    if full_key in device:
        return device[full_key]
    igd_key = f"InternetGatewayDevice.{full_key}"
    if igd_key in device:
        return device[igd_key]
    device_key = f"Device.{full_key}"
    if device_key in device:
        return device[device_key]
    return None


def parse_acs_datetime(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def iter_parameter_values(node: object, parameter_names: set[str]) -> Iterable[tuple[str, object]]:
    if isinstance(node, dict):
        for key, value in node.items():
            matched_name = None
            if key in parameter_names:
                matched_name = key
            else:
                for parameter_name in parameter_names:
                    if key.endswith(f".{parameter_name}"):
                        matched_name = parameter_name
                        break
            if matched_name and isinstance(value, dict) and "_value" in value:
                yield matched_name, value["_value"]
            yield from iter_parameter_values(value, parameter_names)
    elif isinstance(node, list):
        for item in node:
            yield from iter_parameter_values(item, parameter_names)


def collect_parameter_values(node: object, parameter_names: set[str]) -> dict[str, object]:
    values: dict[str, object] = {}
    for key, value in iter_parameter_values(node, parameter_names):
        if key not in values and value not in (None, ""):
            values[key] = value
    return values


def iter_wan_device_nodes(device: dict) -> Iterable[dict]:
    wan_devices = device.get("InternetGatewayDevice", {}).get("WANDevice", {})
    if not isinstance(wan_devices, dict):
        return
    for wan_index, wan_node in wan_devices.items():
        if wan_index.startswith("_") or not isinstance(wan_node, dict):
            continue
        yield wan_node


def iter_wan_connection_nodes(device: dict) -> Iterable[dict]:
    for wan_node in iter_wan_device_nodes(device):
        wan_connection_devices = wan_node.get("WANConnectionDevice")
        if not isinstance(wan_connection_devices, dict):
            continue
        for connection_index, connection_node in wan_connection_devices.items():
            if connection_index.startswith("_") or not isinstance(connection_node, dict):
                continue
            yield connection_node


def get_wan_section_value(device: dict, section_name: str, parameter_name: str) -> object | None:
    for wan_node in iter_wan_device_nodes(device):
        section_node = wan_node.get(section_name)
        if not isinstance(section_node, dict):
            continue
        parameter_node = section_node.get(parameter_name)
        if isinstance(parameter_node, dict) and parameter_node.get("_value") not in (None, ""):
            return parameter_node["_value"]
    return None


def get_wan_connection_stat_value(device: dict, connection_type: str, parameter_name: str) -> object | None:
    for connection_node in iter_wan_connection_nodes(device):
        connection_table = connection_node.get(connection_type)
        if not isinstance(connection_table, dict):
            continue
        for entry_index, entry_node in connection_table.items():
            if entry_index.startswith("_") or not isinstance(entry_node, dict):
                continue
            stats_node = entry_node.get("Stats")
            if not isinstance(stats_node, dict):
                continue
            parameter_node = stats_node.get(parameter_name)
            if isinstance(parameter_node, dict) and parameter_node.get("_value") not in (None, ""):
                return parameter_node["_value"]
    return None


def classify_connection(device: dict) -> str:
    classifier_values = collect_parameter_values(device, {"WANAccessType", "LinkType", "Type"})
    wan_access_types = {str(value).upper() for value in classifier_values.values()}
    if any("DSL" in value for value in wan_access_types):
        return "DSL"
    if any("FIB" in value or "GPON" in value for value in wan_access_types):
        return "Fiber"
    if any("CABLE" in value or "DOCSIS" in value for value in wan_access_types):
        return "Cable"

    layer1_values = collect_parameter_values(device, {"Layer1UpstreamMaxBitRate", "Layer1DownstreamMaxBitRate"})
    layer1_types = {str(value).upper() for value in layer1_values.values()}
    if layer1_types:
        return "DSL"

    return "Unknown"


def extract_traffic_bytes(device: dict) -> tuple[Decimal, Decimal]:
    rx_candidates: list[Decimal] = []
    tx_candidates: list[Decimal] = []

    prioritized_rx_sources = [
        get_wan_section_value(device, "WANCommonInterfaceConfig", "TotalBytesReceived"),
        get_wan_connection_stat_value(device, "WANIPConnection", "EthernetBytesReceived"),
        get_wan_connection_stat_value(device, "WANPPPConnection", "EthernetBytesReceived"),
    ]
    prioritized_tx_sources = [
        get_wan_section_value(device, "WANCommonInterfaceConfig", "TotalBytesSent"),
        get_wan_connection_stat_value(device, "WANIPConnection", "EthernetBytesSent"),
        get_wan_connection_stat_value(device, "WANPPPConnection", "EthernetBytesSent"),
    ]

    for value in prioritized_rx_sources:
        decimal_value = to_decimal(value)
        if decimal_value is not None:
            rx_candidates.append(decimal_value)
    for value in prioritized_tx_sources:
        decimal_value = to_decimal(value)
        if decimal_value is not None:
            tx_candidates.append(decimal_value)

    fallback_rx = [to_decimal(value) for _, value in iter_parameter_values(device, {"TotalBytesReceived", "EthernetBytesReceived"})]
    fallback_tx = [to_decimal(value) for _, value in iter_parameter_values(device, {"TotalBytesSent", "EthernetBytesSent"})]
    rx_candidates.extend(value for value in fallback_rx if value is not None)
    tx_candidates.extend(value for value in fallback_tx if value is not None)

    rx = max(rx_candidates, default=Decimal(0))
    tx = max(tx_candidates, default=Decimal(0))
    return rx, tx


def extract_wan_info(device: dict) -> dict[str, str]:
    wan_params = {
        "ConnectionStatus",
        "ExternalIPAddress",
        "DefaultGateway",
        "DNSServers",
        "Uptime",
        "Name",
        "ConnectionType",
        "NATEnabled",
        "Layer1UpstreamMaxBitRate",
        "Layer1DownstreamMaxBitRate",
        "UpstreamCurrRate",
        "DownstreamCurrRate",
    }
    values = collect_parameter_values(device, wan_params)

    return {
        "status": str(values.get("ConnectionStatus", "-")),
        "external_ip": str(values.get("ExternalIPAddress", "-")),
        "default_gateway": str(values.get("DefaultGateway", "-")),
        "dns_servers": str(values.get("DNSServers", "-")),
        "connection_name": str(values.get("Name", "-")),
        "connection_type": str(values.get("ConnectionType", "-")),
        "nat_enabled": str(values.get("NATEnabled", "-")),
        "uptime_seconds": str(values.get("Uptime", "-")),
        "downstream_max_rate": format_bitrate(values.get("Layer1DownstreamMaxBitRate")),
        "upstream_max_rate": format_bitrate(values.get("Layer1UpstreamMaxBitRate")),
        "downstream_current_rate": format_bitrate(values.get("DownstreamCurrRate")),
        "upstream_current_rate": format_bitrate(values.get("UpstreamCurrRate")),
    }


def extract_wan_common_info(device: dict) -> dict[str, str]:
    common_params = {
        "WANAccessType",
        "LinkType",
        "Type",
        "ConnectionStatus",
        "ConnectionType",
        "ExternalIPAddress",
        "DefaultGateway",
        "DNSServers",
        "NATEnabled",
        "PhysicalLinkStatus",
        "Layer1UpstreamMaxBitRate",
        "Layer1DownstreamMaxBitRate",
        "X_AVM-DE_InternetConnectionLinkType",
    }
    values = collect_parameter_values(device, common_params)

    return {
        "wan_access_type": str(values.get("WANAccessType", "-")),
        "link_type": str(values.get("LinkType", values.get("Type", "-"))),
        "connection_status": str(values.get("ConnectionStatus", "-")),
        "connection_type": str(values.get("ConnectionType", "-")),
        "internet_link_type": str(values.get("X_AVM-DE_InternetConnectionLinkType", "-")),
        "physical_link_status": str(values.get("PhysicalLinkStatus", "-")),
        "external_ip": str(values.get("ExternalIPAddress", "-")),
        "default_gateway": str(values.get("DefaultGateway", "-")),
        "dns_servers": str(values.get("DNSServers", "-")),
        "nat_enabled": str(values.get("NATEnabled", "-")),
        "downstream_max_rate": format_bitrate(values.get("Layer1DownstreamMaxBitRate")),
        "upstream_max_rate": format_bitrate(values.get("Layer1UpstreamMaxBitRate")),
    }


def extract_wan_dsl_info(device: dict) -> dict[str, str]:
    dsl_params = {
        "Status",
        "StandardUsed",
        "CurrentProfile",
        "UpstreamCurrRate",
        "DownstreamCurrRate",
        "UpstreamMaxRate",
        "DownstreamMaxRate",
        "UpstreamNoiseMargin",
        "DownstreamNoiseMargin",
        "LinkEncapsulationUsed",
        "DataPath",
    }
    values = collect_parameter_values(device, dsl_params)

    return {
        "status": str(values.get("Status", "-")),
        "standard_used": str(values.get("StandardUsed", "-")),
        "current_profile": str(values.get("CurrentProfile", "-")),
        "link_encapsulation_used": str(values.get("LinkEncapsulationUsed", "-")),
        "data_path": str(values.get("DataPath", "-")),
        "downstream_current_rate": format_bitrate(values.get("DownstreamCurrRate")),
        "upstream_current_rate": format_bitrate(values.get("UpstreamCurrRate")),
        "downstream_max_rate": format_bitrate(values.get("DownstreamMaxRate")),
        "upstream_max_rate": format_bitrate(values.get("UpstreamMaxRate")),
        "downstream_noise_margin": str(values.get("DownstreamNoiseMargin", "-")),
        "upstream_noise_margin": str(values.get("UpstreamNoiseMargin", "-")),
    }


def extract_wan_cable_info(device: dict) -> dict[str, str]:
    cable_values: dict[str, object] = {
        "WANAccessType": get_wan_section_value(device, "WANCommonInterfaceConfig", "WANAccessType"),
        "PhysicalLinkStatus": get_wan_section_value(device, "WANCommonInterfaceConfig", "PhysicalLinkStatus"),
        "X_AVM-DE_DownstreamCurrentMaxSpeed": get_wan_section_value(
            device, "WANCommonInterfaceConfig", "X_AVM-DE_DownstreamCurrentMaxSpeed"
        ),
        "X_AVM-DE_UpstreamCurrentMaxSpeed": get_wan_section_value(
            device, "WANCommonInterfaceConfig", "X_AVM-DE_UpstreamCurrentMaxSpeed"
        ),
        "X_AVM-DE_DownstreamCurrentUtilization": get_wan_section_value(
            device, "WANCommonInterfaceConfig", "X_AVM-DE_DownstreamCurrentUtilization"
        ),
        "X_AVM-DE_UpstreamCurrentUtilization": get_wan_section_value(
            device, "WANCommonInterfaceConfig", "X_AVM-DE_UpstreamCurrentUtilization"
        ),
        "TotalBytesReceived": get_wan_section_value(device, "WANCommonInterfaceConfig", "TotalBytesReceived"),
        "TotalBytesSent": get_wan_section_value(device, "WANCommonInterfaceConfig", "TotalBytesSent"),
    }
    fallback_values = collect_parameter_values(
        device,
        {
            "X_AVM-DE_DownstreamCurrentMaxSpeed",
            "X_AVM-DE_UpstreamCurrentMaxSpeed",
            "X_AVM-DE_DownstreamCurrentUtilization",
            "X_AVM-DE_UpstreamCurrentUtilization",
            "PhysicalLinkStatus",
            "WANAccessType",
            "TotalBytesReceived",
            "TotalBytesSent",
        },
    )
    values = {key: cable_values.get(key, fallback_values.get(key)) for key in set(cable_values) | set(fallback_values)}

    return {
        "wan_access_type": str(values.get("WANAccessType", "-")),
        "physical_link_status": str(values.get("PhysicalLinkStatus", "-")),
        "downstream_current_max_speed": format_byte_rate(values.get("X_AVM-DE_DownstreamCurrentMaxSpeed")),
        "upstream_current_max_speed": format_byte_rate(values.get("X_AVM-DE_UpstreamCurrentMaxSpeed")),
        "downstream_utilization": str(values.get("X_AVM-DE_DownstreamCurrentUtilization", "-")),
        "upstream_utilization": str(values.get("X_AVM-DE_UpstreamCurrentUtilization", "-")),
        "total_bytes_received": format_bytes(values.get("TotalBytesReceived")),
        "total_bytes_sent": format_bytes(values.get("TotalBytesSent")),
    }


def format_bitrate(raw_value: object) -> str:
    numeric = to_decimal(raw_value)
    if numeric is None:
        return "-"
    return f"{int(numeric):,} bit/s".replace(",", ".")


def format_byte_rate(raw_value: object) -> str:
    numeric = to_decimal(raw_value)
    if numeric is None:
        return "-"
    return f"{int(numeric):,} B/s".replace(",", ".")


def format_bytes(raw_value: object) -> str:
    numeric = to_decimal(raw_value)
    if numeric is None:
        return "-"
    return bytes_to_human(int(numeric))


def extract_wifi_radios(device: dict) -> list[dict[str, str]]:
    radios: list[dict[str, str]] = []
    lan_devices = device.get("InternetGatewayDevice", {}).get("LANDevice", {})
    if not isinstance(lan_devices, dict):
        return radios

    for lan_index, lan_node in lan_devices.items():
        if lan_index.startswith("_") or not isinstance(lan_node, dict):
            continue
        wlan_config = lan_node.get("WLANConfiguration")
        if not isinstance(wlan_config, dict):
            continue
        for wlan_index, wlan_node in wlan_config.items():
            if wlan_index.startswith("_") or not isinstance(wlan_node, dict):
                continue
            radios.append(
                {
                    "interface": f"LAN {lan_index} / WLAN {wlan_index}",
                    "ssid": str(get_nested_acs_value(wlan_node, ["SSID"]) or "-"),
                    "enabled": str(get_nested_acs_value(wlan_node, ["Enable"]) or "-"),
                    "channel": str(get_nested_acs_value(wlan_node, ["Channel"]) or "-"),
                    "standard": str(get_nested_acs_value(wlan_node, ["Standard"]) or "-"),
                    "status": str(get_nested_acs_value(wlan_node, ["Status"]) or "-"),
                    "bssid": str(get_nested_acs_value(wlan_node, ["BSSID"]) or "-"),
                    "max_bitrate": str(get_nested_acs_value(wlan_node, ["MaxBitRate"]) or "-"),
                    "clients": str(get_nested_acs_value(wlan_node, ["TotalAssociations"]) or "-"),
                }
            )

    radios.sort(key=lambda item: item["interface"])
    return radios


def extract_udpst_info(
    device: dict,
    monitor_target: dict[str, object] | None = None,
) -> dict[str, object]:
    raw_json_result = get_nested_acs_value(
        device, ["InternetGatewayDevice", "X_AVM-DE_DiagnosticTools", "IPLayerCapacity", "Result", "Result"]
    ) or ""
    parsed_json_result = parse_udpst_json_result(raw_json_result)
    device_id = str(device.get("_id") or "")
    run_context = get_udpst_run_context(device_id) if device_id else {}
    run_start_iso = str(run_context.get("start_time_iso") or "")
    run_start_time = parse_udpst_output_timestamp(run_start_iso)
    freshness = evaluate_udpst_result_freshness(parsed_json_result, run_start_time)
    chart_points = extract_udpst_result_chart(parsed_json_result)
    incremental_chart = extract_udpst_incremental_chart(parsed_json_result)
    summary = extract_udpst_summary(parsed_json_result)
    debug_details = build_udpst_debug_details(raw_json_result, parsed_json_result, chart_points, incremental_chart, run_context, freshness)

    if monitor_target is None:
        try:
            config_model = AppConfig.query.first()
        except RuntimeError:
            config_model = None
        monitor_target = resolve_udpst_monitor_target(config_model)

    return {
        "test_host": get_nested_acs_value(
            device, ["InternetGatewayDevice", "X_AVM-DE_DiagnosticTools", "IPLayerCapacity", "Config", "Host"]
        )
        or monitor_target.get("host")
        or "-",
        "test_port": get_nested_acs_value(
            device, ["InternetGatewayDevice", "X_AVM-DE_DiagnosticTools", "IPLayerCapacity", "Config", "Port"]
        )
        or str(monitor_target.get("port") or UDPST_TEST_PORT),
        "test_role": get_nested_acs_value(
            device, ["InternetGatewayDevice", "X_AVM-DE_DiagnosticTools", "IPLayerCapacity", "Config", "Role"]
        )
        or UDPST_TEST_ROLE,
        "test_interval_secs": get_nested_acs_value(
            device, ["InternetGatewayDevice", "X_AVM-DE_DiagnosticTools", "IPLayerCapacity", "Config", "TestIntervalSecs"]
        )
        or "-",
        "control_state": get_nested_acs_value(
            device, ["InternetGatewayDevice", "X_AVM-DE_DiagnosticTools", "IPLayerCapacity", "Control", "State"]
        )
        or "-",
        "result_success": get_nested_acs_value(
            device, ["InternetGatewayDevice", "X_AVM-DE_DiagnosticTools", "IPLayerCapacity", "Result", "Success"]
        )
        or "-",
        "result_message": get_nested_acs_value(
            device, ["InternetGatewayDevice", "X_AVM-DE_DiagnosticTools", "IPLayerCapacity", "Result", "Message"]
        )
        or "-",
        "result_json_text": raw_json_result,
        "result_json_pretty": json.dumps(parsed_json_result, ensure_ascii=False, indent=2) if parsed_json_result else "",
        "summary_rows": summary,
        "chart_points": chart_points,
        "chart": incremental_chart,
        "debug_details": debug_details,
        "current_run": {
            "status": str(run_context.get("status") or "idle"),
            "start_time_iso": run_start_iso,
            "trigger_sent": bool(run_context.get("trigger_sent")),
            "device_run_detected": bool(run_context.get("device_run_detected")),
            "completion_detected": bool(run_context.get("completion_detected")),
            "stale_detected": bool(run_context.get("stale_detected")),
            "stale_warning": str(run_context.get("stale_warning") or ""),
            "has_fresh_result": bool(freshness.get("has_fresh_result")),
            "stale_result": bool(freshness.get("stale_result")),
            "bom_time_iso": str(freshness.get("bom_iso") or ""),
            "eom_time_iso": str(freshness.get("eom_iso") or ""),
            "latest_result_time_iso": str(freshness.get("latest_iso") or ""),
        },
    }


def parse_udpst_json_result(raw_result: str) -> dict:
    if not raw_result:
        return {}
    parsed: object = raw_result
    for _ in range(2):
        if isinstance(parsed, dict):
            return parsed
        if not isinstance(parsed, str):
            return {}
        try:
            parsed = json.loads(parsed)
        except (json.JSONDecodeError, TypeError, ValueError):
            return {}
    if isinstance(parsed, dict):
        return parsed
    return {}


def extract_udpst_summary(result_json: dict) -> list[dict[str, str]]:
    if not isinstance(result_json, dict):
        return []
    summary = result_json.get("Output", {}).get("Summary", {})
    if not isinstance(summary, dict):
        return []
    rows: list[dict[str, str]] = []
    for key, value in summary.items():
        rows.append({"label": str(key), "value": str(value)})
    rows.sort(key=lambda item: item["label"].lower())
    return rows


def extract_udpst_result_chart(result_json: dict) -> list[dict[str, object]]:
    if not isinstance(result_json, dict):
        return []

    points: list[dict[str, object]] = []
    max_value = Decimal(0)
    extracted_entries = iter_udpst_numeric_entries(result_json)

    for index, entry in enumerate(extracted_entries, start=1):
        numeric_value = entry.get("numeric_value")
        if not isinstance(numeric_value, Decimal):
            continue
        max_value = max(max_value, numeric_value)
        points.append(
            {
                "label": f"Punkt {index}",
                "value": float(numeric_value),
                "raw_key": str(entry.get("key") or "-"),
                "raw_value": str(entry.get("raw_value") or "-"),
                "percent": 0.0,
                "source_path": str(entry.get("path") or "-"),
            }
        )

    if max_value > 0:
        for point in points:
            point["percent"] = min(100.0, round((Decimal(str(point["value"])) / max_value) * 100, 2))
    return points


def extract_udpst_incremental_chart(result_json: dict) -> dict[str, object]:
    empty_chart = {
        "available": False,
        "labels": [],
        "ip_layer_capacity": [],
        "reordered_ratio_percent": [],
        "message": "Kein IncrementalResult im UDPST-Ergebnis gefunden.",
    }
    if not isinstance(result_json, dict):
        return empty_chart

    output = result_json.get("Output", {})
    if not isinstance(output, dict):
        return empty_chart

    incremental = output.get("IncrementalResult")
    if incremental is None:
        return empty_chart

    rows: list[dict[str, object]] = []
    if isinstance(incremental, list):
        rows = [row for row in incremental if isinstance(row, dict)]
    elif isinstance(incremental, dict):
        if any(key in incremental for key in ("Interval", "Seconds", "IPLayerCapacity", "ReorderedRatio")):
            rows = [incremental]
        else:
            sorted_items = sorted(incremental.items(), key=lambda item: str(item[0]))
            rows = [value for key, value in sorted_items if not str(key).startswith("_") and isinstance(value, dict)]

    if not rows:
        empty_chart["message"] = "IncrementalResult ist vorhanden, enthält aber keine verwertbaren Intervalldaten."
        return empty_chart

    labels: list[str] = []
    ip_layer_capacity: list[float] = []
    reordered_ratio_percent: list[float] = []
    for index, row in enumerate(rows, start=1):
        interval_value = row.get("Interval")
        if interval_value in (None, ""):
            interval_value = row.get("Seconds")
        ip_value = to_decimal(row.get("IPLayerCapacity"))
        reordered_ratio = to_decimal(row.get("ReorderedRatio"))
        if interval_value in (None, "") or ip_value is None or reordered_ratio is None:
            continue
        labels.append(str(interval_value))
        ip_layer_capacity.append(float(ip_value))
        reordered_ratio_percent.append(float((reordered_ratio * Decimal(100)).quantize(Decimal("0.0001"))))

    if not labels:
        empty_chart["message"] = (
            "IncrementalResult gefunden, aber keine vollständigen Messpunkte mit Interval/Seconds, "
            "IPLayerCapacity und ReorderedRatio."
        )
        return empty_chart

    return {
        "available": True,
        "labels": labels,
        "ip_layer_capacity": ip_layer_capacity,
        "reordered_ratio_percent": reordered_ratio_percent,
        "message": "",
        "points": len(labels),
    }


def iter_udpst_numeric_entries(node: object, path: str = "Result") -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            current_path = f"{path}.{key}"
            numeric_value = to_decimal(value)
            if numeric_value is not None:
                entries.append(
                    {
                        "key": key,
                        "raw_value": value,
                        "numeric_value": numeric_value,
                        "path": current_path,
                    }
                )
            entries.extend(iter_udpst_numeric_entries(value, current_path))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            current_path = f"{path}[{index}]"
            numeric_value = to_decimal(value)
            if numeric_value is not None:
                entries.append(
                    {
                        "key": f"[{index}]",
                        "raw_value": value,
                        "numeric_value": numeric_value,
                        "path": current_path,
                    }
                )
            entries.extend(iter_udpst_numeric_entries(value, current_path))
    return entries


def build_udpst_debug_details(
    raw_result: str,
    parsed_result: dict,
    chart_points: list[dict[str, object]],
    incremental_chart: dict[str, object],
    run_context: dict[str, object],
    freshness: dict[str, object],
) -> list[dict[str, str]]:
    output = parsed_result.get("Output", {}) if isinstance(parsed_result, dict) else {}
    incremental = output.get("IncrementalResult") if isinstance(output, dict) else None
    incremental_kind = type(incremental).__name__ if incremental is not None else "missing"
    first_point = chart_points[0] if chart_points else {}
    return [
        {"label": "Result.Result Länge", "value": str(len(raw_result or ""))},
        {"label": "JSON parsebar", "value": "Ja" if bool(parsed_result) else "Nein"},
        {"label": "IncrementalResult Typ", "value": incremental_kind},
        {"label": "Diagramm-Punkte", "value": str(len(chart_points))},
        {"label": "Incremental-Chart verfügbar", "value": "Ja" if bool(incremental_chart.get("available")) else "Nein"},
        {"label": "Incremental-Messpunkte", "value": str(incremental_chart.get("points") or 0)},
        {"label": "Erster Punkt Quelle", "value": str(first_point.get("source_path") or "-")},
        {"label": "Aktueller Lauf Startzeitpunkt (UTC)", "value": str(run_context.get("start_time_iso") or "-")},
        {"label": "Output.BOMTime", "value": str(freshness.get("bom_iso") or freshness.get("bom_raw") or "-")},
        {"label": "Output.EOMTime", "value": str(freshness.get("eom_iso") or freshness.get("eom_raw") or "-")},
        {"label": "stale_result", "value": "Ja" if bool(freshness.get("stale_result")) else "Nein"},
        {"label": "new_result_for_current_run", "value": "Ja" if bool(freshness.get("has_fresh_result")) else "Nein"},
    ]


def update_udpst_ajax_job(job_id: str, **kwargs) -> dict[str, object]:
    with UDPST_AJAX_LOCK:
        current = dict(UDPST_AJAX_JOBS.get(job_id, {}))
        current.update(kwargs)
        current["updated_at"] = datetime.now(UTC).isoformat(timespec="seconds")
        UDPST_AJAX_JOBS[job_id] = current
        return dict(current)


def finish_udpst_ajax_job(job_id: str, state: str, **kwargs) -> dict[str, object]:
    job = update_udpst_ajax_job(job_id, state=state, **kwargs)
    device_id = str(job.get("device_id") or "")
    if device_id:
        with UDPST_AJAX_LOCK:
            if UDPST_AJAX_DEVICE_JOBS.get(device_id) == job_id:
                UDPST_AJAX_DEVICE_JOBS.pop(device_id, None)
    return job


def run_udpst_ajax_job(
    acs_api_url: str,
    device_id: str,
    job_id: str,
    selected_role: str,
    monitor_target: dict[str, object],
) -> None:
    try:
        update_udpst_ajax_job(job_id, state="running", phase=1, progress=10, status_text="Aktuelle ACS-Konfiguration wird gelesen")
        device = load_device_detail(acs_api_url, device_id, monitor_target=monitor_target)
        if not device:
            finish_udpst_ajax_job(job_id, "failed", error="Gerät wurde im ACS nicht gefunden.", progress=100)
            return

        udpst = device.get("udpst", {}) if isinstance(device, dict) else {}
        current_host = str(udpst.get("test_host") or "").strip()
        current_port = str(udpst.get("test_port") or "").strip()
        current_role = str(udpst.get("test_role") or "").strip()
        current_interval_raw = udpst.get("test_interval_secs")

        target_host = str(monitor_target.get("host") or "").strip()
        target_port = monitor_target.get("port")
        if not target_host or target_port is None:
            finish_udpst_ajax_job(
                job_id,
                "failed",
                error="UDPST-Start fehlgeschlagen: Host oder Port sind nicht konfiguriert.",
                progress=100,
            )
            return

        desired_port = str(target_port)
        updates: list[tuple[str, object, str]] = []
        update_udpst_ajax_job(
            job_id,
            phase=2,
            progress=20,
            status_text="Abweichungen werden geprüft",
            acs_snapshot={
                "host": current_host,
                "port": current_port,
                "role": current_role,
                "test_interval_secs": current_interval_raw,
            },
        )
        if current_host != target_host:
            updates.append(("InternetGatewayDevice.X_AVM-DE_DiagnosticTools.IPLayerCapacity.Config.Host", target_host, "xsd:string"))
        if current_port != desired_port:
            updates.append(("InternetGatewayDevice.X_AVM-DE_DiagnosticTools.IPLayerCapacity.Config.Port", int(target_port), "xsd:unsignedInt"))
        if current_role != selected_role:
            updates.append(("InternetGatewayDevice.X_AVM-DE_DiagnosticTools.IPLayerCapacity.Config.Role", selected_role, "xsd:string"))

        if updates:
            update_udpst_ajax_job(job_id, phase=3, progress=35, status_text="Host/Port/Role werden aktualisiert")
            queue_set_parameter_values_task(acs_api_url, device_id, updates)
        else:
            update_udpst_ajax_job(job_id, phase=3, progress=35, status_text="Config bereits korrekt, kein Schreibvorgang nötig")

        refreshed = load_device_detail(acs_api_url, device_id, monitor_target=monitor_target)
        udpst_ref = refreshed.get("udpst", {}) if isinstance(refreshed, dict) else {}
        interval_decimal = to_decimal(udpst_ref.get("test_interval_secs"))
        if interval_decimal is None or interval_decimal <= 0:
            finish_udpst_ajax_job(job_id, "failed", error="Ungültige oder fehlende Config.TestIntervalSecs.", progress=100)
            return
        interval_seconds = int(interval_decimal)
        wait_seconds = interval_seconds + 2
        update_udpst_ajax_job(job_id, test_interval_secs=interval_seconds, wait_seconds=wait_seconds)

        update_udpst_ajax_job(job_id, phase=4, progress=45, status_text="Control.Start=true wird gesetzt")
        queue_set_parameter_values_task(
            acs_api_url,
            device_id,
            [("InternetGatewayDevice.X_AVM-DE_DiagnosticTools.IPLayerCapacity.Control.Start", True, "xsd:boolean")],
        )

        update_udpst_ajax_job(job_id, phase=5, progress=55, status_text=f"Wartephase läuft ({wait_seconds}s)", wait_remaining=wait_seconds)
        for remaining in range(wait_seconds, -1, -1):
            update_udpst_ajax_job(job_id, wait_remaining=remaining, progress=min(75, 55 + int(((wait_seconds - remaining) / max(wait_seconds, 1)) * 20)))
            time.sleep(1)

        update_udpst_ajax_job(job_id, phase=6, progress=80, status_text="Result.Message wird abgefragt")
        queue_get_parameter_values_task(
            acs_api_url,
            device_id,
            ["InternetGatewayDevice.X_AVM-DE_DiagnosticTools.IPLayerCapacity.Result.Message"],
        )
        result_device = load_device_detail(acs_api_url, device_id, monitor_target=monitor_target)
        result_udpst = result_device.get("udpst", {}) if isinstance(result_device, dict) else {}
        result_message = str(result_udpst.get("result_message") or "").strip()

        if result_message:
            finish_udpst_ajax_job(
                job_id,
                "completed",
                phase=8,
                progress=100,
                status_text="Ergebnis wird angezeigt",
                result_message=result_message,
                result_result="",
                device_udpst=result_udpst,
            )
            return

        update_udpst_ajax_job(job_id, phase=7, progress=90, status_text="Result.Result wird abgefragt")
        queue_get_parameter_values_task(
            acs_api_url,
            device_id,
            ["InternetGatewayDevice.X_AVM-DE_DiagnosticTools.IPLayerCapacity.Result.Result"],
        )
        final_device = load_device_detail(acs_api_url, device_id, monitor_target=monitor_target)
        final_udpst = final_device.get("udpst", {}) if isinstance(final_device, dict) else {}
        result_result = str(final_udpst.get("result_json_text") or "").strip()
        if not result_result:
            finish_udpst_ajax_job(
                job_id,
                "failed",
                error="Result.Result ist leer oder ungültig.",
                phase=8,
                progress=100,
                device_udpst=final_udpst,
            )
            return

        finish_udpst_ajax_job(
            job_id,
            "completed",
            phase=8,
            progress=100,
            status_text="Ergebnis wird angezeigt",
            result_message="",
            result_result=result_result,
            device_udpst=final_udpst,
        )
    except requests.RequestException:
        finish_udpst_ajax_job(job_id, "failed", error="ACS nicht erreichbar.", progress=100)
    except Exception as exc:
        finish_udpst_ajax_job(job_id, "failed", error=f"Unerwarteter Fehler: {exc}", progress=100)


def queue_set_parameter_values_task(
    acs_api_url: str,
    device_id: str,
    parameter_values: list[tuple[str, object, str]],
) -> None:
    task_url = build_acs_task_url(acs_api_url, device_id, connection_request=True)
    payload = {
        "name": "setParameterValues",
        "parameterValues": [[name, value, value_type] for name, value, value_type in parameter_values],
    }
    append_udpst_debug_trace(device_id, "acs->task", f"setParameterValues: {json.dumps(payload, ensure_ascii=False)}")
    response = requests.post(task_url, json=payload, timeout=10)
    response.raise_for_status()
    append_udpst_debug_trace(device_id, "acs<-status", f"HTTP {response.status_code} setParameterValues")


def queue_get_parameter_values_task(
    acs_api_url: str,
    device_id: str,
    parameter_names: list[str],
) -> None:
    task_url = build_acs_task_url(acs_api_url, device_id, connection_request=True)
    payload = {
        "name": "getParameterValues",
        "parameterNames": parameter_names,
    }
    append_udpst_debug_trace(device_id, "acs->task", f"getParameterValues: {json.dumps(payload, ensure_ascii=False)}")
    response = requests.post(task_url, json=payload, timeout=10)
    response.raise_for_status()
    append_udpst_debug_trace(device_id, "acs<-status", f"HTTP {response.status_code} getParameterValues")


def queue_connection_request_task(acs_api_url: str, device_id: str) -> None:
    task_url = build_acs_task_url(acs_api_url, device_id, connection_request=False)
    payload = {"name": "connection_request"}
    append_udpst_debug_trace(device_id, "acs->task", f"connection_request: {json.dumps(payload, ensure_ascii=False)}")
    response = requests.post(task_url, json=payload, timeout=10)
    response.raise_for_status()
    append_udpst_debug_trace(device_id, "acs<-status", f"HTTP {response.status_code} connection_request")


def build_acs_task_url(acs_api_url: str, device_id: str, connection_request: bool = False) -> str:
    suffix = "?timeout=10000&connection_request" if connection_request else "?timeout=10000"
    return f"{acs_api_url}/devices/{quote(device_id, safe='')}/tasks{suffix}"


def determine_udpst_polling(device: dict | None) -> tuple[int, int, int]:
    configured_interval = to_decimal(
        get_nested_acs_value(
            device or {},
            ["InternetGatewayDevice", "X_AVM-DE_DiagnosticTools", "IPLayerCapacity", "Config", "TestIntervalSecs"],
        )
    )
    test_interval_seconds = int(configured_interval) if configured_interval is not None and configured_interval > 0 else 60
    timeout_seconds = max(30, test_interval_seconds + 30)
    poll_interval_seconds = 3
    return test_interval_seconds, timeout_seconds, poll_interval_seconds


def poll_udpst_result(
    acs_api_url: str,
    device_id: str,
    timeout_seconds: int = 90,
    poll_interval_seconds: int = 3,
    start_time: datetime | None = None,
) -> dict[str, bool]:
    deadline = datetime.now(UTC) + timedelta(seconds=timeout_seconds)
    state = {
        "trigger_sent": bool(get_udpst_run_context(device_id).get("trigger_sent")),
        "device_run_detected": False,
        "running_seen": False,
        "not_started_no_running": False,
        "result_observed": False,
        "stale_result_detected": False,
        "completed_with_fresh_result": False,
        "timeout": False,
    }
    append_udpst_debug_trace(device_id, "poll", f"Polling gestartet (timeout={timeout_seconds}s, interval={poll_interval_seconds}s)")
    if start_time:
        append_udpst_debug_trace(device_id, "poll", f"Vergleich gegen Startzeitpunkt (UTC): {start_time.isoformat()}")
    previous_control_state = ""
    first_state_change_logged = False
    fresh_time_logged = False
    while datetime.now(UTC) < deadline:
        queue_get_parameter_values_task(acs_api_url, device_id, UDPST_STATUS_PARAMETER_NAMES)
        device = load_device_detail(acs_api_url, device_id)
        if not device:
            append_udpst_debug_trace(device_id, "poll", "Gerätedetails leer, nächster Poll")
            continue
        udpst_info = device.get("udpst", {}) if isinstance(device, dict) else {}
        control_state = str(udpst_info.get("control_state", "")).strip()
        result_message = str(udpst_info.get("result_message", "")).strip()
        result_success = str(udpst_info.get("result_success", "")).strip()
        result_json_text = str(udpst_info.get("result_json_text", "")).strip()
        parsed_result = parse_udpst_json_result(result_json_text)
        freshness = evaluate_udpst_result_freshness(parsed_result, start_time)
        stale_result = bool(freshness.get("stale_result"))
        has_fresh_result = bool(freshness.get("has_fresh_result"))
        bom_time_iso = str(freshness.get("bom_iso") or freshness.get("bom_raw") or "-")
        eom_time_iso = str(freshness.get("eom_iso") or freshness.get("eom_raw") or "-")
        control_state_is_running = control_state.lower() == UDPST_RUNNING_STATE
        if control_state_is_running:
            state["device_run_detected"] = True
            state["running_seen"] = True
            update_udpst_run_context(device_id, status="device_run_detected", device_run_detected=True)
        if control_state != previous_control_state and not first_state_change_logged:
            append_udpst_debug_trace(
                device_id,
                "poll",
                f"Control.State Wechsel erkannt: '{previous_control_state or '-'}' -> '{control_state or '-'}'",
            )
            first_state_change_logged = True
        previous_control_state = control_state
        append_udpst_debug_trace(
            device_id,
            "poll-snapshot",
            (
                f"State={control_state or '-'} Success={result_success or '-'} Message={result_message or '-'} "
                f"JSON={'ja' if bool(result_json_text) else 'nein'} BOMTime={bom_time_iso} EOMTime={eom_time_iso} "
                f"stale_result={'true' if stale_result else 'false'}"
            ),
        )
        has_any_result = result_message not in {"", "-"} or result_success not in {"", "-"} or bool(result_json_text)
        if has_any_result:
            state["result_observed"] = True
        if has_any_result and stale_result and state["running_seen"]:
            state["stale_result_detected"] = True
            update_udpst_run_context(
                device_id,
                status="stale_result_detected",
                stale_detected=True,
                stale_warning="Es wurde kein neuer Testlauf erkannt. Das gelesene Ergebnis stammt offenbar von einem früheren Lauf.",
            )
            append_udpst_debug_trace(device_id, "poll", "Ergebnis vorhanden, aber als stale erkannt")
        if has_fresh_result and not fresh_time_logged:
            append_udpst_debug_trace(
                device_id,
                "poll",
                f"Frisches Ergebnis mit BOMTime={bom_time_iso} EOMTime={eom_time_iso} erkannt",
            )
            fresh_time_logged = True
        if state["running_seen"] and control_state and not control_state_is_running and has_fresh_result:
            state["completed_with_fresh_result"] = True
            update_udpst_run_context(
                device_id,
                status="completed",
                completion_detected=True,
                stale_detected=False,
                stale_warning="",
            )
            append_udpst_debug_trace(device_id, "poll", "Finales Ergebnis erkannt und zeitlich als neuer Lauf bestätigt")
            return state
        if poll_interval_seconds > 0:
            time.sleep(poll_interval_seconds)
    state["timeout"] = True
    if state["trigger_sent"] and not state["running_seen"]:
        state["not_started_no_running"] = True
        update_udpst_run_context(
            device_id,
            status="not_started_no_running",
            stale_detected=False,
            stale_warning=(
                "Der Start-Trigger wurde gesendet, aber Control.State wechselte nicht auf running. "
                "Der Test wurde daher nicht gestartet."
            ),
        )
        append_udpst_debug_trace(
            device_id,
            "poll",
            "Timeout: Control.State wurde zu keinem Zeitpunkt 'running' -> Test gilt als nicht gestartet.",
        )
        return state
    if state["stale_result_detected"]:
        update_udpst_run_context(device_id, status="timeout_stale_only")
    elif state["trigger_sent"]:
        update_udpst_run_context(device_id, status="timeout_no_new_result")
    append_udpst_debug_trace(device_id, "poll", "Timeout erreicht ohne finales, frisches Ergebnis")
    return state


def append_udpst_debug_trace(device_id: str, stage: str, message: str) -> None:
    entry = {
        "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
        "stage": stage,
        "message": message,
    }
    with UDPST_DEBUG_LOCK:
        trace = UDPST_DEBUG_TRACES.setdefault(device_id, [])
        trace.append(entry)
        if len(trace) > UDPST_DEBUG_MAX_ENTRIES:
            del trace[: len(trace) - UDPST_DEBUG_MAX_ENTRIES]


def get_udpst_debug_trace(device_id: str) -> list[dict[str, str]]:
    with UDPST_DEBUG_LOCK:
        trace = UDPST_DEBUG_TRACES.get(device_id, [])
        return list(trace)


def clear_udpst_debug_trace(device_id: str) -> None:
    with UDPST_DEBUG_LOCK:
        UDPST_DEBUG_TRACES[device_id] = []


def set_udpst_run_context(device_id: str, context: dict[str, object]) -> None:
    with UDPST_RUN_CONTEXT_LOCK:
        UDPST_RUN_CONTEXTS[device_id] = dict(context)


def update_udpst_run_context(device_id: str, **kwargs) -> dict[str, object]:
    with UDPST_RUN_CONTEXT_LOCK:
        current = dict(UDPST_RUN_CONTEXTS.get(device_id, {}))
        current.update(kwargs)
        UDPST_RUN_CONTEXTS[device_id] = current
        return dict(current)


def get_udpst_run_context(device_id: str) -> dict[str, object]:
    with UDPST_RUN_CONTEXT_LOCK:
        return dict(UDPST_RUN_CONTEXTS.get(device_id, {}))


def parse_udpst_output_timestamp(value: object) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        numeric = float(value)
        if numeric > 1e12:
            numeric /= 1000.0
        try:
            return datetime.fromtimestamp(numeric, UTC)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        text_value = value.strip()
        if not text_value:
            return None
        try:
            numeric = float(text_value)
            if numeric > 1e12:
                numeric /= 1000.0
            return datetime.fromtimestamp(numeric, UTC)
        except (TypeError, ValueError, OverflowError, OSError):
            pass
        normalized = text_value.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    return None


def evaluate_udpst_result_freshness(parsed_result: dict, start_time: datetime | None) -> dict[str, object]:
    output = parsed_result.get("Output", {}) if isinstance(parsed_result, dict) else {}
    bom_raw = output.get("BOMTime") if isinstance(output, dict) else None
    eom_raw = output.get("EOMTime") if isinstance(output, dict) else None
    bom_time = parse_udpst_output_timestamp(bom_raw)
    eom_time = parse_udpst_output_timestamp(eom_raw)
    latest_time = max([candidate for candidate in [bom_time, eom_time] if candidate is not None], default=None)
    stale_result = False
    has_fresh_result = False
    if start_time and latest_time:
        stale_result = latest_time < start_time
        has_fresh_result = latest_time >= start_time
    elif start_time and (bom_time or eom_time):
        has_fresh_result = any(candidate and candidate >= start_time for candidate in [bom_time, eom_time])
        stale_result = not has_fresh_result
    return {
        "bom_raw": str(bom_raw or ""),
        "eom_raw": str(eom_raw or ""),
        "bom_iso": bom_time.isoformat() if bom_time else "",
        "eom_iso": eom_time.isoformat() if eom_time else "",
        "latest_iso": latest_time.isoformat() if latest_time else "",
        "has_timestamp": bool(bom_time or eom_time),
        "stale_result": stale_result,
        "has_fresh_result": has_fresh_result,
    }


def resolve_udpst_server_addresses(host: str, port: int) -> list[tuple]:
    return socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)


def check_udpst_server_running(addresses: list[tuple]) -> bool:
    for _, _, _, _, sockaddr in addresses:
        try:
            with socket.create_connection(sockaddr, UDPST_HEALTHCHECK_TIMEOUT_SECONDS):
                return True
        except OSError:
            continue
    return False


def resolve_udpst_monitor_target(config: AppConfig | None) -> dict[str, object]:
    udpst_url = (config.udpst_server_url if config else "").strip() if config else ""
    udpst_port = config.udpst_server_port if config else None
    host = extract_udpst_host(udpst_url)
    port = udpst_port if isinstance(udpst_port, int) else None
    return {"url": udpst_url, "host": host, "port": port}


def get_udpst_server_status(config: AppConfig | None) -> dict[str, object]:
    target = resolve_udpst_monitor_target(config)
    host = str(target.get("host") or "")
    port = target.get("port")
    if not host or port is None:
        return {"is_running": False, "host": "-", "port": "-", "error": "Nicht konfiguriert."}

    try:
        addresses = resolve_udpst_server_addresses(host, int(port))
    except OSError:
        return {
            "is_running": False,
            "host": host,
            "port": port,
            "error": "Host nicht auflösbar.",
        }

    tcp_reachable = check_udpst_server_running(addresses)
    return {
        "is_running": True,
        "host": host,
        "port": port,
        "error": None if tcp_reachable else "Host erreichbar, Portprüfung ohne TCP-Antwort.",
    }


def extract_udpst_host(raw_value: str) -> str:
    value = (raw_value or "").strip()
    if not value:
        return ""

    parse_target = value if "://" in value else f"//{value}"
    parsed_url = urlparse(parse_target)
    return parsed_url.hostname or ""


def to_decimal(value: object) -> Decimal | None:
    if value is None:
        return None
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None


def admin_required():
    if not current_user.is_authenticated or current_user.role != "admin":
        flash("Keine Berechtigung.", "warning")
        return False
    return True


def ensure_app_config_columns() -> None:
    table_info = db.session.execute(text("PRAGMA table_info(app_config)")).fetchall()
    existing_columns = {row[1] for row in table_info}

    if "udpst_server_url" not in existing_columns:
        db.session.execute(text("ALTER TABLE app_config ADD COLUMN udpst_server_url VARCHAR(500) NOT NULL DEFAULT ''"))
    if "udpst_server_port" not in existing_columns:
        db.session.execute(
            text(f"ALTER TABLE app_config ADD COLUMN udpst_server_port INTEGER NOT NULL DEFAULT {UDPST_TEST_PORT}")
        )
    db.session.commit()


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if not admin_required():
        return redirect(url_for("dashboard"))

    config = AppConfig.query.first()
    if config is None:
        config = AppConfig(acs_api_url="http://genieacs:7557", udpst_server_url="", udpst_server_port=UDPST_TEST_PORT)
        db.session.add(config)
        db.session.commit()

    if request.method == "POST":
        acs_api_url = request.form.get("acs_api_url", "").strip()
        udpst_server_url = request.form.get("udpst_server_url", "").strip()
        udpst_server_port_raw = request.form.get("udpst_server_port", "").strip()
        if not acs_api_url:
            flash("ACS-API-URL darf nicht leer sein.", "danger")
            return render_template("settings.html", config=config, udpst_server_status=get_udpst_server_status(config))
        if not udpst_server_url:
            flash("UDPST-Server-URL darf nicht leer sein.", "danger")
            return render_template("settings.html", config=config, udpst_server_status=get_udpst_server_status(config))

        host = extract_udpst_host(udpst_server_url)
        if not host:
            flash("UDPST-Server muss eine Hostname- oder IP-Angabe enthalten.", "danger")
            return render_template("settings.html", config=config, udpst_server_status=get_udpst_server_status(config))

        try:
            ip_address(host)
        except ValueError:
            if "." not in host or " " in host:
                flash("UDPST-Server-URL muss eine gültige Domain oder IP-Adresse enthalten.", "danger")
                return render_template("settings.html", config=config, udpst_server_status=get_udpst_server_status(config))

        try:
            udpst_server_port = int(udpst_server_port_raw)
        except ValueError:
            flash("UDPST-Port muss eine Zahl zwischen 1 und 65535 sein.", "danger")
            return render_template("settings.html", config=config, udpst_server_status=get_udpst_server_status(config))

        if udpst_server_port < 1 or udpst_server_port > 65535:
            flash("UDPST-Port muss eine Zahl zwischen 1 und 65535 sein.", "danger")
            return render_template("settings.html", config=config, udpst_server_status=get_udpst_server_status(config))

        config.acs_api_url = acs_api_url
        config.udpst_server_url = udpst_server_url
        config.udpst_server_port = udpst_server_port
        config.updated_at = datetime.now(UTC)
        db.session.commit()
        flash("Einstellungen gespeichert.", "success")
        return redirect(url_for("settings"))

    return render_template("settings.html", config=config, udpst_server_status=get_udpst_server_status(config))


@app.route("/users", methods=["GET", "POST"])
@login_required
def users():
    if not admin_required():
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "viewer")

        if role not in {"admin", "editor", "viewer"}:
            flash("Ungültige Rolle.", "danger")
            return redirect(url_for("users"))

        if not username or not password:
            flash("Benutzername und Passwort sind erforderlich.", "danger")
            return redirect(url_for("users"))

        if User.query.filter_by(username=username).first():
            flash("Benutzername existiert bereits.", "danger")
            return redirect(url_for("users"))

        user = User(username=username, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Benutzer erstellt.", "success")
        return redirect(url_for("users"))

    all_users = User.query.order_by(User.username.asc()).all()
    return render_template("users.html", users=all_users)


@app.post("/users/<int:user_id>/delete")
@login_required
def delete_user(user_id: int):
    if not admin_required():
        return redirect(url_for("dashboard"))

    user = db.session.get(User, user_id)
    if user is None:
        flash("Benutzer nicht gefunden.", "warning")
        return redirect(url_for("users"))

    if user.id == current_user.id:
        flash("Du kannst deinen eigenen Benutzer nicht löschen.", "danger")
        return redirect(url_for("users"))

    db.session.delete(user)
    db.session.commit()
    flash("Benutzer gelöscht.", "info")
    return redirect(url_for("users"))


with app.app_context():
    db.create_all()
    ensure_app_config_columns()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
