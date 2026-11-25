"""Multi-application registry and lifecycle for the RIZVI WAF reverse proxies."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import ssl
import tempfile
import threading
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, TypedDict
from urllib.parse import urlsplit, urlunsplit

from waf import BLOCK_THRESHOLD, RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECONDS
from waf import RULES, FirewallEvent, StatsSnapshot, WAFProxy


MAX_APPLICATIONS = 100
MAX_RECORDED_EVENTS = 1000
MAX_CUSTOM_RULES = 20
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,79}$")
_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class ApplicationView(TypedDict):
    id: str
    name: str
    backend_url: str
    hostnames: list[str]
    listen_port: int
    authorized: bool
    enabled_rule_ids: list[str]
    rule_weights: dict[str, int]
    block_threshold: int
    allowlist_ips: list[str]
    blocklist_ips: list[str]
    path_bypasses: list[str]
    rate_limit_window_seconds: int
    rate_limit_max_requests: int
    custom_rules: list[dict[str, str]]
    tls_certfile: str | None
    tls_keyfile: str | None
    connection_status: str
    connection_error: str
    protection_status: str
    is_protected: bool
    stats: StatsSnapshot
    event_count: int
    recorded_attack_count: int
    log_error: str


@dataclass(frozen=True)
class ApplicationSpec:
    id: str
    name: str
    backend_url: str
    hostnames: tuple[str, ...]
    listen_port: int
    authorized: bool
    enabled_rule_ids: tuple[str, ...]
    rule_weights: dict[str, int]
    block_threshold: int
    allowlist_ips: tuple[str, ...]
    blocklist_ips: tuple[str, ...]
    path_bypasses: tuple[str, ...]
    rate_limit_window_seconds: int
    rate_limit_max_requests: int
    custom_rules: tuple[tuple[str, str], ...]
    tls_certfile: str | None = None
    tls_keyfile: str | None = None

    @classmethod
    def from_data(cls, data: dict[str, object]) -> ApplicationSpec:
        if not isinstance(data, dict):
            raise ValueError("An application configuration must be an object.")

        app_id = data.get("id")
        if app_id is None:
            app_id = uuid.uuid4().hex
        if not isinstance(app_id, str):
            raise ValueError("Application ID must be a UUID.")
        try:
            app_id = uuid.UUID(app_id).hex
        except ValueError as exc:
            raise ValueError("Application ID must be a UUID.") from exc

        name = data.get("name")
        if not isinstance(name, str) or not _NAME_RE.fullmatch(name.strip()):
            raise ValueError(
                "Application name must be 1–80 letters, numbers, spaces, dots, "
                "underscores, or hyphens."
            )
        name = name.strip()

        backend_url = data.get("backend_url")
        if not isinstance(backend_url, str):
            raise ValueError("Backend URL must be a string.")
        backend_url = cls._normalise_backend_url(backend_url)
        hostname_values = data.get("hostnames", [])
        if (
            not isinstance(hostname_values, (list, tuple))
            or any(not isinstance(hostname, str) for hostname in hostname_values)
        ):
            raise ValueError("Application hostnames must be a list of domain names or IPs.")
        hostnames = tuple(
            dict.fromkeys(cls._normalise_hostname(hostname) for hostname in hostname_values)
        )

        listen_port = data.get("listen_port")
        if type(listen_port) is not int or not 1 <= listen_port <= 65535:
            raise ValueError("WAF listen port must be an integer from 1 to 65535.")

        authorized = data.get("authorized")
        if type(authorized) is not bool or not authorized:
            raise PermissionError(
                "Registering an application requires explicit authorization confirmation."
            )

        known_rule_ids = {rule.id for rule in RULES}
        enabled_values = data.get("enabled_rule_ids", [rule.id for rule in RULES])
        if (
            not isinstance(enabled_values, (list, tuple))
            or any(not isinstance(rule_id, str) for rule_id in enabled_values)
        ):
            raise ValueError("Enabled rule IDs must be a list of strings.")
        enabled_rule_ids = tuple(dict.fromkeys(enabled_values))
        if not enabled_rule_ids or not set(enabled_rule_ids) <= known_rule_ids:
            raise ValueError("At least one known inspection rule must be enabled.")

        weights_value = data.get(
            "rule_weights",
            {rule.id: rule.weight for rule in RULES},
        )
        if not isinstance(weights_value, dict) or set(weights_value) != known_rule_ids:
            raise ValueError("Rule weights must contain every known WAF rule.")
        if any(
            type(weight) is not int or not 1 <= weight <= 100
            for weight in weights_value.values()
        ):
            raise ValueError("Rule weights must be integers from 1 to 100.")
        weights = dict(weights_value)

        threshold = data.get("block_threshold", BLOCK_THRESHOLD)
        if type(threshold) is not int or not 1 <= threshold <= 100:
            raise ValueError("Block threshold must be an integer from 1 to 100.")

        allowlist = cls._normalise_ip_list("allowlist_ips", data.get("allowlist_ips", []))
        blocklist = cls._normalise_ip_list("blocklist_ips", data.get("blocklist_ips", []))
        bypasses_value = data.get("path_bypasses", [])
        if (
            not isinstance(bypasses_value, (list, tuple))
            or any(not isinstance(path, str) for path in bypasses_value)
        ):
            raise ValueError("Path bypasses must be a list of path strings.")
        bypasses: list[str] = []
        for path in bypasses_value:
            if (
                not path.startswith("/")
                or path.startswith("//")
                or "?" in path
                or "#" in path
                or len(path) > 240
            ):
                raise ValueError(f"Invalid exact path bypass: {path!r}")
            if path not in bypasses:
                bypasses.append(path)

        rate_window = data.get(
            "rate_limit_window_seconds",
            RATE_LIMIT_WINDOW_SECONDS,
        )
        rate_limit = data.get("rate_limit_max_requests", RATE_LIMIT_MAX_REQUESTS)
        if type(rate_window) is not int or not 1 <= rate_window <= 3600:
            raise ValueError("Rate-limit window must be from 1 to 3600 seconds.")
        if type(rate_limit) is not int or not 1 <= rate_limit <= 1_000_000:
            raise ValueError("Rate limit must be from 1 to 1000000 requests.")

        custom_value = data.get("custom_rules", [])
        if not isinstance(custom_value, (list, tuple)) or len(custom_value) > MAX_CUSTOM_RULES:
            raise ValueError(f"Custom rules must be a list of at most {MAX_CUSTOM_RULES} items.")
        custom_rules: list[tuple[str, str]] = []
        for item in custom_value:
            if not isinstance(item, dict):
                raise ValueError("Each custom rule must have a name and a literal pattern.")
            rule_name = item.get("name")
            literal = item.get("pattern")
            if (
                not isinstance(rule_name, str)
                or not rule_name.strip()
                or len(rule_name.strip()) > 80
                or not isinstance(literal, str)
                or not literal
                or len(literal) > 200
            ):
                raise ValueError("Custom rule names and literal patterns must be bounded.")
            custom_rules.append((rule_name.strip(), literal))

        cert_value = data.get("tls_certfile")
        key_value = data.get("tls_keyfile")
        if cert_value is not None and not isinstance(cert_value, str):
            raise ValueError("TLS certificate path must be a string.")
        if key_value is not None and not isinstance(key_value, str):
            raise ValueError("TLS private key path must be a string.")
        certfile = cert_value or None
        keyfile = key_value or None
        if (certfile is None) != (keyfile is None):
            raise ValueError("Both TLS certificate and private key paths are required.")

        return cls(
            id=app_id,
            name=name,
            backend_url=backend_url,
            hostnames=hostnames,
            listen_port=listen_port,
            authorized=authorized,
            enabled_rule_ids=enabled_rule_ids,
            rule_weights=weights,
            block_threshold=threshold,
            allowlist_ips=tuple(allowlist),
            blocklist_ips=tuple(blocklist),
            path_bypasses=tuple(bypasses),
            rate_limit_window_seconds=rate_window,
            rate_limit_max_requests=rate_limit,
            custom_rules=tuple(custom_rules),
            tls_certfile=certfile,
            tls_keyfile=keyfile,
        )

    @staticmethod
    def _normalise_hostname(value: str) -> str:
        hostname = value.strip().rstrip(".")
        if not hostname or any(char.isspace() or char in "/@?#[]" for char in hostname):
            raise ValueError(f"Invalid application hostname: {value!r}")
        try:
            return ipaddress.ip_address(hostname).compressed.lower()
        except ValueError:
            if ":" in hostname:
                raise ValueError(f"Invalid application hostname: {value!r}")
            try:
                normalized = hostname.encode("idna").decode("ascii").lower()
            except UnicodeError as exc:
                raise ValueError(f"Invalid application hostname: {value!r}") from exc
            if (
                len(normalized) > 253
                or any(not _DOMAIN_LABEL_RE.fullmatch(label) for label in normalized.split("."))
            ):
                raise ValueError(f"Invalid application hostname: {value!r}")
            return normalized

    @staticmethod
    def _normalise_backend_url(value: str) -> str:
        value = value.strip()
        if not value or any(char.isspace() or ord(char) < 32 for char in value):
            raise ValueError("Backend URL must not be empty or contain whitespace.")
        try:
            parsed = urlsplit(value)
            host = parsed.hostname
            port = parsed.port
        except ValueError as exc:
            raise ValueError(f"Invalid backend URL: {exc}") from exc
        if parsed.scheme.lower() not in {"http", "https"} or not host:
            raise ValueError("Backend URL must use http:// or https:// and include a host.")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Backend URLs must not contain embedded credentials.")
        if parsed.query or parsed.fragment or "?" in value or "#" in value:
            raise ValueError("Backend URL cannot include a query or fragment.")
        if parsed.path.startswith("//"):
            raise ValueError("Backend URL path must not begin with //.")

        try:
            ip = ipaddress.ip_address(host)
            normalized_host = ip.compressed
            netloc_host = f"[{normalized_host}]" if ip.version == 6 else normalized_host
        except ValueError:
            try:
                normalized_host = host.rstrip(".").encode("idna").decode("ascii").lower()
            except UnicodeError as exc:
                raise ValueError("Backend domain name is invalid.") from exc
            if (
                len(normalized_host) > 253
                or not normalized_host
                or any(not _DOMAIN_LABEL_RE.fullmatch(label) for label in normalized_host.split("."))
            ):
                raise ValueError("Backend domain name is invalid.")
            netloc_host = normalized_host

        if port is not None and not 1 <= port <= 65535:
            raise ValueError("Backend port must be from 1 to 65535.")
        netloc = netloc_host + (f":{port}" if port is not None else "")
        path = parsed.path.rstrip("/")
        return urlunsplit((parsed.scheme.lower(), netloc, path, "", ""))

    @staticmethod
    def _normalise_ip_list(field_name: str, values: object) -> list[str]:
        if (
            not isinstance(values, (list, tuple))
            or any(not isinstance(value, str) for value in values)
        ):
            raise ValueError(f"{field_name} must be a list of IP or CIDR strings.")
        result: list[str] = []
        for value in values:
            try:
                canonical = str(ipaddress.ip_network(value.strip(), strict=False))
            except ValueError as exc:
                raise ValueError(f"Invalid {field_name} entry: {value!r}") from exc
            if canonical not in result:
                result.append(canonical)
        return result

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "name": self.name,
            "backend_url": self.backend_url,
            "hostnames": list(self.hostnames),
            "listen_port": self.listen_port,
            "authorized": self.authorized,
            "enabled_rule_ids": list(self.enabled_rule_ids),
            "rule_weights": dict(self.rule_weights),
            "block_threshold": self.block_threshold,
            "allowlist_ips": list(self.allowlist_ips),
            "blocklist_ips": list(self.blocklist_ips),
            "path_bypasses": list(self.path_bypasses),
            "rate_limit_window_seconds": self.rate_limit_window_seconds,
            "rate_limit_max_requests": self.rate_limit_max_requests,
            "custom_rules": [
                {"name": name, "pattern": pattern}
                for name, pattern in self.custom_rules
            ],
            "tls_certfile": self.tls_certfile,
            "tls_keyfile": self.tls_keyfile,
        }


@dataclass
class _ApplicationRecord:
    spec: ApplicationSpec
    proxy: WAFProxy | None = None
    last_stats: StatsSnapshot | None = None
    connection_status: str = "Untested"
    connection_error: str = ""
    events: deque[dict[str, object]] = field(
        default_factory=lambda: deque(maxlen=MAX_RECORDED_EVENTS)
    )
    event_count: int = 0
    attack_count: int = 0
    log_error: str = ""


class ApplicationRegistry:
    """Stores authorized fixed-destination applications and owns their proxies."""

    def __init__(
        self,
        *,
        event_callback: Callable[[str, FirewallEvent], None] | None = None,
        change_callback: Callable[[], None] | None = None,
        log_directory: Path | None = None,
        audit_path: Path | None = None,
        applications: Iterable[dict[str, object]] = (),
    ) -> None:
        self._lock = threading.RLock()
        self._applications: dict[str, _ApplicationRecord] = {}
        self._event_callback = event_callback
        self._change_callback = change_callback
        self._log_directory = log_directory or Path.home() / ".rizvi-waf" / "events"
        self._audit_path = audit_path or Path.home() / ".rizvi-waf" / "audit.jsonl"
        self._log_directory.mkdir(parents=True, exist_ok=True)
        self._audit_path.parent.mkdir(parents=True, exist_ok=True)
        specs = self.validate_catalog(applications)
        for spec in specs:
            record = _ApplicationRecord(spec=spec)
            self._load_event_history(record)
            self._applications[spec.id] = record

    @staticmethod
    def validate_catalog(
        applications: Iterable[dict[str, object]],
    ) -> tuple[ApplicationSpec, ...]:
        specs = tuple(ApplicationSpec.from_data(value) for value in applications)
        if len(specs) > MAX_APPLICATIONS:
            raise ValueError(f"At most {MAX_APPLICATIONS} applications may be registered.")
        if len({spec.id for spec in specs}) != len(specs):
            raise ValueError("Application IDs must be unique.")
        if len({spec.listen_port for spec in specs}) != len(specs):
            raise ValueError("Each application must use a unique WAF listen port.")
        if len({spec.name.casefold() for spec in specs}) != len(specs):
            raise ValueError("Application names must be unique.")
        return specs

    @staticmethod
    def _require_confirmation(confirmed: bool) -> None:
        if confirmed is not True:
            raise PermissionError("Administrator confirmation is required for this action.")

    def _get_record(self, app_id: str) -> _ApplicationRecord:
        try:
            return self._applications[app_id]
        except KeyError as exc:
            raise KeyError(f"Unknown application ID: {app_id}") from exc

    def _ensure_unique(
        self,
        spec: ApplicationSpec,
        *,
        ignore_id: str | None = None,
    ) -> None:
        if len(self._applications) >= MAX_APPLICATIONS and ignore_id is None:
            raise ValueError(f"At most {MAX_APPLICATIONS} applications may be registered.")
        if spec.id in self._applications and spec.id != ignore_id:
            raise ValueError(f"Application ID {spec.id!r} is already registered.")
        for app_id, record in self._applications.items():
            if app_id == ignore_id:
                continue
            if record.spec.listen_port == spec.listen_port:
                raise ValueError(f"WAF listen port {spec.listen_port} is already assigned.")
            if record.spec.name.casefold() == spec.name.casefold():
                raise ValueError(f"Application name {spec.name!r} is already registered.")

    def _audit(
        self,
        app_id: str,
        action: str,
        outcome: str,
        detail: str = "",
        *,
        application_name: str | None = None,
    ) -> None:
        record = self._applications.get(app_id)
        entry = {
            "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
            "application_id": app_id,
            "application_name": (
                application_name
                if application_name is not None
                else record.spec.name if record is not None else ""
            ),
            "action": action,
            "outcome": outcome,
            "detail": detail[:500],
        }
        try:
            with self._audit_path.open("a", encoding="utf-8", newline="\n") as audit_file:
                audit_file.write(json.dumps(entry, ensure_ascii=True) + "\n")
                audit_file.flush()
                os.fsync(audit_file.fileno())
        except OSError as exc:
            raise OSError(f"Could not write administrator audit log: {exc}") from exc

    def _changed(self) -> None:
        if self._change_callback is not None:
            self._change_callback()

    def add_application(
        self,
        data: dict[str, object],
        *,
        confirmed: bool = False,
    ) -> ApplicationSpec:
        self._require_confirmation(confirmed)
        spec = ApplicationSpec.from_data(data)
        with self._lock:
            self._ensure_unique(spec)
            if len(self._applications) >= MAX_APPLICATIONS:
                raise ValueError(f"At most {MAX_APPLICATIONS} applications may be registered.")
            self._audit(
                spec.id,
                "register",
                "confirmed",
                application_name=spec.name,
            )
            record = _ApplicationRecord(spec=spec)
            self._applications[spec.id] = record
            self._changed()
            return spec

    def update_application(
        self,
        app_id: str,
        changes: dict[str, object],
        *,
        confirmed: bool = False,
    ) -> ApplicationSpec:
        self._require_confirmation(confirmed)
        with self._lock:
            record = self._get_record(app_id)
            if record.proxy is not None and record.proxy.is_running:
                raise RuntimeError("Stop protection before editing an application.")
            merged = record.spec.to_dict()
            merged.update(changes)
            merged["id"] = app_id
            spec = ApplicationSpec.from_data(merged)
            self._ensure_unique(spec, ignore_id=app_id)
            self._audit(app_id, "edit", "confirmed")
            record.spec = spec
            self._changed()
            return spec

    def test_connection(self, app_id: str, *, confirmed: bool = False) -> str:
        self._require_confirmation(confirmed)
        with self._lock:
            record = self._get_record(app_id)
            spec = record.spec
        self._audit(app_id, "connect_test", "started")
        parsed = urlsplit(spec.backend_url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            addresses = WAFProxy._resolve_backend_addresses(parsed.hostname or "", port)
        except ValueError as exc:
            with self._lock:
                record = self._get_record(app_id)
                record.connection_status = "Unavailable"
                record.connection_error = str(exc)
                self._audit(app_id, "connect_test", "failed", record.connection_error)
                self._changed()
            raise
        last_error: OSError | ssl.SSLError | None = None
        for address in addresses:
            try:
                connection = socket.create_connection((address, port), timeout=3)
                try:
                    if parsed.scheme == "https":
                        context = ssl.create_default_context()
                        secure_connection = context.wrap_socket(
                            connection,
                            server_hostname=parsed.hostname,
                        )
                        secure_connection.close()
                finally:
                    connection.close()
                last_error = None
                break
            except (OSError, ssl.SSLError) as exc:
                last_error = exc
        with self._lock:
            record = self._get_record(app_id)
            if last_error is None:
                record.connection_status = "Reachable"
                record.connection_error = ""
                self._audit(app_id, "connect_test", "reachable")
            else:
                record.connection_status = "Unavailable"
                record.connection_error = f"{type(last_error).__name__}: {last_error}"
                self._audit(app_id, "connect_test", "failed", record.connection_error)
                self._changed()
                raise OSError(f"Backend connection failed: {record.connection_error}") from last_error
            self._changed()
            return record.connection_status

    def start_protection(self, app_id: str, *, confirmed: bool = False) -> int:
        self._require_confirmation(confirmed)
        with self._lock:
            record = self._get_record(app_id)
            if record.proxy is not None and record.proxy.is_running:
                raise RuntimeError("Protection is already running for this application.")
            spec = record.spec
            self._audit(app_id, "start_protection", "requested")
            proxy: WAFProxy | None = None
            try:
                proxy = WAFProxy(
                    spec.backend_url,
                    spec.listen_port,
                    lambda event, identifier=app_id: self._record_event(identifier, event),
                    allowlist_ips=spec.allowlist_ips,
                    blocklist_ips=spec.blocklist_ips,
                    allowlist_paths=tuple(
                        re.compile(rf"^{re.escape(path)}$")
                        for path in spec.path_bypasses
                    ),
                    allowed_hosts=spec.hostnames,
                    rate_limit_window_seconds=spec.rate_limit_window_seconds,
                    rate_limit_max_requests=spec.rate_limit_max_requests,
                    tls_certfile=spec.tls_certfile,
                    tls_keyfile=spec.tls_keyfile,
                )
                proxy.configure_policy(
                    set(spec.enabled_rule_ids),
                    spec.rule_weights,
                    spec.block_threshold,
                    spec.allowlist_ips,
                    spec.blocklist_ips,
                    tuple(
                        re.compile(rf"^{re.escape(path)}$")
                        for path in spec.path_bypasses
                    ),
                    spec.rate_limit_window_seconds,
                    spec.rate_limit_max_requests,
                    spec.custom_rules,
                )
                proxy.start()
                self._audit(app_id, "start_protection", "listening")
            except (OSError, ValueError, RuntimeError) as exc:
                if proxy is not None:
                    proxy.stop()
                try:
                    self._audit(app_id, "start_protection", "failed", str(exc))
                except OSError as audit_error:
                    raise OSError(f"{exc}; {audit_error}") from exc
                raise
            if proxy is None:
                raise RuntimeError("WAF proxy initialization did not produce a proxy.")
            record.proxy = proxy
            self._changed()
            return proxy.port

    def stop_protection(self, app_id: str, *, confirmed: bool = False) -> None:
        self._require_confirmation(confirmed)
        with self._lock:
            record = self._get_record(app_id)
            self._audit(app_id, "stop_protection", "requested")
            if record.proxy is not None:
                record.proxy.stop()
                record.last_stats = record.proxy.stats()
                record.proxy = None
            self._audit(app_id, "stop_protection", "stopped")
            self._changed()

    def update_security(
        self,
        app_id: str,
        changes: dict[str, object],
        *,
        confirmed: bool = False,
    ) -> ApplicationSpec:
        self._require_confirmation(confirmed)
        with self._lock:
            record = self._get_record(app_id)
            merged = record.spec.to_dict()
            merged.update(changes)
            merged["id"] = app_id
            spec = ApplicationSpec.from_data(merged)
            proxy = record.proxy if record.proxy is not None and record.proxy.is_running else None
            self._audit(app_id, "update_security", "confirmed")
            if proxy is not None:
                proxy.configure_policy(
                    set(spec.enabled_rule_ids),
                    spec.rule_weights,
                    spec.block_threshold,
                    spec.allowlist_ips,
                    spec.blocklist_ips,
                    tuple(
                        re.compile(rf"^{re.escape(path)}$")
                        for path in spec.path_bypasses
                    ),
                    spec.rate_limit_window_seconds,
                    spec.rate_limit_max_requests,
                    spec.custom_rules,
                )
            record.spec = spec
            self._changed()
            return spec

    def disconnect(self, app_id: str, *, confirmed: bool = False) -> None:
        self._require_confirmation(confirmed)
        with self._lock:
            record = self._get_record(app_id)
            self._audit(app_id, "disconnect", "requested")
            if record.proxy is not None:
                record.proxy.stop()
                record.last_stats = record.proxy.stats()
            del self._applications[app_id]
            self._changed()

    def shutdown(self) -> None:
        errors: list[str] = []
        with self._lock:
            records = list(self._applications.values())
        for record in records:
            proxy = record.proxy
            if proxy is None:
                continue
            try:
                self._audit(record.spec.id, "application_shutdown", "requested")
            except OSError as exc:
                errors.append(str(exc))
            try:
                proxy.stop()
            except OSError as exc:
                errors.append(f"{record.spec.name}: {exc}")
                continue
            record.last_stats = proxy.stats()
            record.proxy = None
        if errors:
            raise OSError("; ".join(errors))

    def protection_status(self, app_id: str) -> str:
        with self._lock:
            record = self._get_record(app_id)
            proxy = record.proxy
        if proxy is None or not proxy.is_running:
            return "Stopped"
        if proxy.stats()["inspected"] > 0:
            return "Protected"
        return "Listening — awaiting inspected traffic"

    def list_applications(self) -> list[ApplicationView]:
        with self._lock:
            records = list(self._applications.values())
        applications: list[ApplicationView] = []
        for record in records:
            proxy = record.proxy
            stats = self._record_stats(record)
            spec = record.spec
            applications.append(
                {
                    "id": spec.id,
                    "name": spec.name,
                    "backend_url": spec.backend_url,
                    "hostnames": list(spec.hostnames),
                    "listen_port": spec.listen_port,
                    "authorized": spec.authorized,
                    "enabled_rule_ids": list(spec.enabled_rule_ids),
                    "rule_weights": dict(spec.rule_weights),
                    "block_threshold": spec.block_threshold,
                    "allowlist_ips": list(spec.allowlist_ips),
                    "blocklist_ips": list(spec.blocklist_ips),
                    "path_bypasses": list(spec.path_bypasses),
                    "rate_limit_window_seconds": spec.rate_limit_window_seconds,
                    "rate_limit_max_requests": spec.rate_limit_max_requests,
                    "custom_rules": [
                        {"name": name, "pattern": pattern}
                        for name, pattern in spec.custom_rules
                    ],
                    "tls_certfile": spec.tls_certfile,
                    "tls_keyfile": spec.tls_keyfile,
                    "connection_status": record.connection_status,
                    "connection_error": record.connection_error,
                    "protection_status": self.protection_status(spec.id),
                    "is_protected": bool(
                        proxy is not None
                        and proxy.is_running
                        and stats["inspected"] > 0
                    ),
                    "stats": stats,
                    "event_count": record.event_count,
                    "recorded_attack_count": record.attack_count,
                    "log_error": record.log_error,
                }
            )
        return applications

    def application_events(
        self,
        app_id: str,
        *,
        attacks_only: bool = False,
    ) -> list[dict[str, object]]:
        with self._lock:
            record = self._get_record(app_id)
            events = list(record.events)
        if attacks_only:
            events = [event for event in events if event.get("action") == "BLOCKED"]
        return events

    def generate_report(self, app_id: str, destination: Path) -> dict[str, object]:
        with self._lock:
            record = self._get_record(app_id)
            spec = record.spec
            events = list(record.events)
            event_count = record.event_count
        stats = self._record_stats(record)
        attacks = [event for event in events if event.get("action") == "BLOCKED"]
        report: dict[str, object] = {
            "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "application": {
                "id": spec.id,
                "name": spec.name,
                "backend_url": spec.backend_url,
                "hostnames": list(spec.hostnames),
                "listen_port": spec.listen_port,
            },
            "security_policy": {
                "enabled_rule_ids": list(spec.enabled_rule_ids),
                "rule_weights": dict(spec.rule_weights),
                "block_threshold": spec.block_threshold,
                "allowlist_ips": list(spec.allowlist_ips),
                "blocklist_ips": list(spec.blocklist_ips),
                "path_bypasses": list(spec.path_bypasses),
                "rate_limit_window_seconds": spec.rate_limit_window_seconds,
                "rate_limit_max_requests": spec.rate_limit_max_requests,
                "custom_rules": [
                    {"name": name, "pattern": pattern}
                    for name, pattern in spec.custom_rules
                ],
            },
            "connection_status": self._get_record(app_id).connection_status,
            "protection_status": self.protection_status(app_id),
            "session_statistics": stats,
            "recorded_event_count": event_count,
            "recorded_attack_count": record.attack_count,
            "recent_attack_count": len(attacks),
            "attacks": attacks,
            "recent_events": events,
        }
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                newline="\n",
                dir=destination.parent,
                prefix=f".{destination.name}.",
                suffix=".tmp",
                delete=False,
            ) as report_file:
                temporary_path = Path(report_file.name)
                json.dump(report, report_file, indent=2, ensure_ascii=True)
                report_file.write("\n")
                report_file.flush()
                os.fsync(report_file.fileno())
            os.replace(temporary_path, destination)
        except OSError:
            if temporary_path is not None:
                try:
                    temporary_path.unlink()
                except FileNotFoundError:
                    pass
                except OSError:
                    pass
            raise
        return report

    def configurations(self) -> list[dict[str, object]]:
        with self._lock:
            return [record.spec.to_dict() for record in self._applications.values()]

    def _record_event(self, app_id: str, event: FirewallEvent) -> None:
        serialized = asdict(event)
        serialized["application_id"] = app_id
        with self._lock:
            record = self._applications.get(app_id)
            if record is None:
                return
            record.events.append(serialized)
            record.event_count += 1
            if event.action == "BLOCKED":
                record.attack_count += 1
            if event.status == 502 and event.detail.startswith("Backend error:"):
                record.connection_status = "Unavailable"
                record.connection_error = event.detail
            elif event.action == "ALLOWED" and event.status != 502:
                record.connection_status = "Reachable"
                record.connection_error = ""
            try:
                with (self._log_directory / f"{app_id}.jsonl").open(
                    "a",
                    encoding="utf-8",
                    newline="\n",
                ) as event_file:
                    event_file.write(json.dumps(serialized, ensure_ascii=True) + "\n")
                    event_file.flush()
                    os.fsync(event_file.fileno())
            except OSError as exc:
                record.log_error = f"Could not save event history: {exc}"
        if self._event_callback is not None:
            self._event_callback(app_id, event)

    @staticmethod
    def _record_stats(record: _ApplicationRecord) -> StatsSnapshot:
        if record.proxy is not None and record.proxy.is_running:
            return record.proxy.stats()
        if record.last_stats is not None:
            return record.last_stats
        return {
            "total": 0,
            "inspected": 0,
            "allowed": 0,
            "blocked": 0,
            "block_ratio": 0.0,
            "by_rule": {},
            "top_clients": [],
            "uptime_seconds": 0.0,
        }

    def _load_event_history(self, record: _ApplicationRecord) -> None:
        event_path = self._log_directory / f"{record.spec.id}.jsonl"
        valid_lines: list[str] = []
        recovery_message: str | None = None
        try:
            with event_path.open("r", encoding="utf-8") as event_file:
                for line_number, line in enumerate(event_file, start=1):
                    if not line.strip():
                        valid_lines.append(line)
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError as exc:
                        recovery_message = (
                            f"Invalid event history at line {line_number}: {exc}"
                        )
                        break
                    if not isinstance(event, dict) or event.get("application_id") != record.spec.id:
                        recovery_message = (
                            f"Event history application ID is invalid at line {line_number}."
                        )
                        break
                    record.event_count += 1
                    if event.get("action") == "BLOCKED":
                        record.attack_count += 1
                    record.events.append(event)
                    valid_lines.append(line)
        except FileNotFoundError:
            return
        except UnicodeError as exc:
            recovery_message = f"Event history has invalid text encoding: {exc}"
        except OSError as exc:
            record.log_error = f"Could not load event history: {exc}"
            return

        if recovery_message is not None:
            temporary_path: Path | None = None
            try:
                quarantine_path = event_path.with_name(
                    f"{event_path.name}.corrupt-{datetime.now():%Y%m%d%H%M%S}-"
                    f"{uuid.uuid4().hex[:8]}"
                )
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    newline="\n",
                    dir=event_path.parent,
                    prefix=f".{event_path.name}.",
                    suffix=".tmp",
                    delete=False,
                ) as recovered_file:
                    temporary_path = Path(recovered_file.name)
                    recovered_file.writelines(valid_lines)
                    recovered_file.flush()
                    os.fsync(recovered_file.fileno())
                os.replace(event_path, quarantine_path)
                try:
                    os.replace(temporary_path, event_path)
                except OSError:
                    os.replace(quarantine_path, event_path)
                    raise
                record.log_error = (
                    f"{recovery_message}; original preserved as {quarantine_path.name}"
                )
            except OSError as exc:
                record.log_error = (
                    f"{recovery_message}; history recovery failed: {exc}"
                )
                if temporary_path is not None:
                    try:
                        temporary_path.unlink()
                    except FileNotFoundError:
                        pass
                    except OSError:
                        pass
