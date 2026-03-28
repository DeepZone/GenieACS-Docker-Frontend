import json
import os
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from urllib.parse import quote

import requests
from flask import Flask, flash, redirect, render_template, request, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
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
    "DeviceID.SerialNumber",
    "DeviceInfo.ModelName",
    "InternetGatewayDevice.DeviceInfo.ModelName",
]

DEVICE_DETAIL_PROJECTION_FIELDS = [
    "_id",
    "_lastInform",
    "DeviceID.Manufacturer",
    "DeviceID.ProductClass",
    "DeviceID.SerialNumber",
    "DeviceInfo.ModelName",
    "InternetGatewayDevice.DeviceInfo.ModelName",
    "InternetGatewayDevice.WANDevice",
    "InternetGatewayDevice.LANDevice",
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

        config = AppConfig(acs_api_url=acs_api_url, updated_at=datetime.now(UTC))

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

    return render_template(
        "device_detail.html",
        config=config,
        device=device,
        detail_error=detail_error,
        online_window_minutes=ONLINE_WINDOW_MINUTES,
    )


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

        rows.append(
            {
                "device_id": device.get("_id", "unbekannt"),
                "manufacturer": get_device_identity_value(device, "manufacturer"),
                "product_class": get_device_identity_value(device, "product_class"),
                "serial_number": get_device_identity_value(device, "serial_number"),
                "model": get_device_identity_value(device, "model"),
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


def load_device_detail(acs_api_url: str, device_id: str) -> dict | None:
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

    return {
        "device_id": device.get("_id", "unbekannt"),
        "manufacturer": get_device_identity_value(device, "manufacturer"),
        "product_class": get_device_identity_value(device, "product_class"),
        "serial_number": get_device_identity_value(device, "serial_number"),
        "model": get_device_identity_value(device, "model"),
        "last_inform": last_inform,
        "is_online": is_online,
        "connection_class": connection_class,
        "total_rx_bytes": int(rx),
        "total_tx_bytes": int(tx),
        "internet_sections": internet_sections,
        "wifi_radios": wifi_radios,
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


def get_device_identity_value(device: dict, field_name: str) -> str:
    value_paths: dict[str, list[list[str]]] = {
        "manufacturer": [["DeviceID", "Manufacturer"], ["DeviceInfo", "Manufacturer"]],
        "product_class": [["DeviceID", "ProductClass"], ["DeviceInfo", "ProductClass"]],
        "serial_number": [["DeviceID", "SerialNumber"], ["DeviceInfo", "SerialNumber"]],
        "model": [
            ["DeviceInfo", "ModelName"],
            ["InternetGatewayDevice", "DeviceInfo", "ModelName"],
        ],
    }

    for path in value_paths.get(field_name, []):
        value = get_nested_acs_value(device, path)
        if value:
            return value

    return "-"


def get_nested_acs_value(device: dict, path: list[str]) -> str | None:
    node: object = device
    for segment in path:
        if not isinstance(node, dict) or segment not in node:
            return None
        node = node[segment]

    if isinstance(node, dict):
        if "_value" in node and node["_value"] is not None:
            value = str(node["_value"]).strip()
            return value or None
        return None

    value = str(node).strip()
    return value or None


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
            if key in parameter_names and isinstance(value, dict) and "_value" in value:
                yield key, value["_value"]
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
    rx_names = {"TotalBytesReceived", "BytesReceived", "EthernetBytesReceived"}
    tx_names = {"TotalBytesSent", "BytesSent", "EthernetBytesSent"}

    rx_values = [to_decimal(value) for _, value in iter_parameter_values(device, rx_names)]
    tx_values = [to_decimal(value) for _, value in iter_parameter_values(device, tx_names)]

    rx_values = [value for value in rx_values if value is not None]
    tx_values = [value for value in tx_values if value is not None]

    rx = max(rx_values, default=Decimal(0))
    tx = max(tx_values, default=Decimal(0))
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
    cable_params = {
        "X_AVM-DE_DownstreamCurrentMaxSpeed",
        "X_AVM-DE_UpstreamCurrentMaxSpeed",
        "X_AVM-DE_DownstreamCurrentUtilization",
        "X_AVM-DE_UpstreamCurrentUtilization",
        "PhysicalLinkStatus",
        "WANAccessType",
    }
    values = collect_parameter_values(device, cable_params)

    return {
        "wan_access_type": str(values.get("WANAccessType", "-")),
        "physical_link_status": str(values.get("PhysicalLinkStatus", "-")),
        "downstream_current_max_speed": format_byte_rate(values.get("X_AVM-DE_DownstreamCurrentMaxSpeed")),
        "upstream_current_max_speed": format_byte_rate(values.get("X_AVM-DE_UpstreamCurrentMaxSpeed")),
        "downstream_utilization": str(values.get("X_AVM-DE_DownstreamCurrentUtilization", "-")),
        "upstream_utilization": str(values.get("X_AVM-DE_UpstreamCurrentUtilization", "-")),
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


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if not admin_required():
        return redirect(url_for("dashboard"))

    config = AppConfig.query.first()
    if config is None:
        config = AppConfig(acs_api_url="http://genieacs:7557")
        db.session.add(config)
        db.session.commit()

    if request.method == "POST":
        acs_api_url = request.form.get("acs_api_url", "").strip()
        if not acs_api_url:
            flash("ACS-API-URL darf nicht leer sein.", "danger")
            return render_template("settings.html", config=config)

        config.acs_api_url = acs_api_url
        config.updated_at = datetime.now(UTC)
        db.session.commit()
        flash("Einstellungen gespeichert.", "success")
        return redirect(url_for("settings"))

    return render_template("settings.html", config=config)


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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
