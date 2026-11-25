from __future__ import annotations

import http.client
import ipaddress
import json
import re
import socket
import ssl
import threading
import time
import zlib
from collections import defaultdict, deque
from dataclasses import dataclass, replace
from datetime import datetime
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Iterable, Mapping, TypedDict
from urllib.parse import unquote_plus, urlsplit

# --------------------------------------------------------------------------- #
# Tunables
# --------------------------------------------------------------------------- #
MAX_REQUEST_BODY = 1_048_576            # 1 MiB
MAX_HEADER_BYTES = 32_768               # 32 KiB of headers
UPSTREAM_TIMEOUT_SECONDS = 10
MAX_UPSTREAM_RESPONSE_BYTES = 5_000_000  # 5 MB

BLOCK_THRESHOLD = 3                     # weighted score to auto-block
RATE_LIMIT_WINDOW_SECONDS = 10
RATE_LIMIT_MAX_REQUESTS = 120           # per IP per window
SHUTDOWN_GRACE_SECONDS = 5

INSPECT_RESPONSES = False               # flip to True to scan upstream bodies
HEALTH_PATH = "/__waf/health"

# --------------------------------------------------------------------------- #
# Rule set — id, human name, weight, regex
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    weight: int
    pattern: re.Pattern[str]


def _r(rule_id: str, name: str, weight: int, pattern: str) -> Rule:
    return Rule(rule_id, name, weight, re.compile(pattern, re.IGNORECASE | re.DOTALL))


RULES: tuple[Rule, ...] = (
    # --- Injection ---
    _r("SQLI-01", "SQL injection (UNION SELECT)", 5,
       r"\bunion\s+(?:all\s+)?select\b"),
    _r("SQLI-02", "SQL injection (tautology)", 4,
       r"\bor\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|\band\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+"),
    _r("SQLI-03", "SQL injection (DDL/DML)", 4,
       r"\b(?:drop|insert|update|delete)\s+(?:table|from|into)\b"),
    _r("SQLI-04", "SQL comment / block", 2, r"--\s|/\*"),

    # --- XSS ---
    _r("XSS-01", "Script tag", 5, r"<\s*script\b"),
    _r("XSS-02", "JavaScript URI", 4, r"javascript\s*:"),
    _r("XSS-03", "Inline event handler", 3, r"on(?:error|load|click|mouseover)\s*="),
    _r("XSS-04", "Iframe / object tag", 3, r"<\s*(?:iframe|object|embed)\b"),

    # --- Traversal / LFI ---
    _r("LFI-01", "Path traversal", 4, r"(?:\.\.[\\/])+"),
    _r("LFI-02", "Sensitive file probe", 3,
       r"(?:/etc/passwd|/etc/shadow|/proc/self/|win\.ini|boot\.ini|\.htaccess|web\.config)"),

    # --- RCE / command injection ---
    _r("RCE-01", "Shell metachar chain", 4,
       r"[;&|`]\s*(?:cat|ls|wget|curl|nc|bash|sh|powershell|cmd)\b"),
    _r("RCE-02", "Log4Shell JNDI", 6, r"\$\{jndi:(?:ldap|rmi|dns|http)s?://"),
    _r("RCE-03", "Expression language injection", 4,
       r"\$\{(?:jndi|env|sys|pageContext|applicationScope):"),

    # --- XXE / SSRF ---
    _r("XXE-01", "XML external entity", 5, r"<!DOCTYPE[^>]*\[|<!ENTITY\b"),
    _r("SSRF-01", "SSRF (cloud metadata)", 5,
       r"169\.254\.169\.254|metadata\.google\.internal|/latest/meta-data/"),

    # --- Protocol abuse ---
    _r("CRLF-01", "CRLF injection", 3, r"%0d%0a|%0a%0d|[\r\n]\s*(?:set-cookie|location):"),
    _r("SCAN-01", "Vulnerability scanner UA", 2,
       r"(?:sqlmap|nikto|nmap|acunetix|nessus|openvas|masscan|zgrab|wpscan)"),

    # --- Sensitive paths ---
    _r("PATH-01", "Admin probe", 1,
       r"/(?:wp-admin|wp-login|phpmyadmin|admin|manager/html|\.git/|\.env\b)"),
)


BLOCKED_METHODS = {
    "TRACE", "TRACK", "CONNECT",   # request smuggling / tunnelling helpers
}


# --------------------------------------------------------------------------- #
# Event dataclass — extended but backward compatible
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class FirewallEvent:
    timestamp: str
    action: str                 # ALLOWED | BLOCKED
    method: str
    path: str
    client: str
    status: int
    detail: str
    severity: str = "INFO"      # INFO | WARN | BLOCK  (new, defaults preserve compat)
    rule_id: str = ""           # new
    score: int = 0              # new
    inspected: bool = False


@dataclass(frozen=True)
class InspectionResult:
    blocked: bool
    rule_ids: tuple[str, ...]
    rule_names: tuple[str, ...]
    score: int
    reason: str


class UnsupportedContentEncoding(ValueError):
    pass


class RequestBodyTooLarge(ValueError):
    pass


class UnsupportedCharacterEncoding(ValueError):
    pass


class StatsSnapshot(TypedDict):
    total: int
    inspected: int
    allowed: int
    blocked: int
    block_ratio: float
    by_rule: dict[str, int]
    top_clients: list[tuple[str, int]]
    uptime_seconds: float


# --------------------------------------------------------------------------- #
# Pure inspection logic
# --------------------------------------------------------------------------- #
def _decode_payload(text: str) -> str:
    """Double-decode to defeat single-pass obfuscation."""
    once = unquote_plus(text)
    try:
        twice = unquote_plus(once)
    except Exception:
        twice = once
    return twice


def inspect_full(
    path: str,
    headers: dict[str, str],
    body: bytes,
    content_type: str = "",
    rules: Iterable[Rule] = RULES,
    block_threshold: int = BLOCK_THRESHOLD,
) -> InspectionResult:
    """Score a request against every rule. Return a rich result."""
    header_text = " ".join(f"{k}: {v}" for k, v in headers.items())
    content_type_header = Message()
    if content_type:
        content_type_header["content-type"] = content_type
    charset = content_type_header.get_content_charset()
    if charset is None:
        bom_encodings = (
            (b"\x00\x00\xfe\xff", "utf-32"),
            (b"\xff\xfe\x00\x00", "utf-32"),
            (b"\xfe\xff", "utf-16"),
            (b"\xff\xfe", "utf-16"),
        )
        charset = next(
            (encoding for marker, encoding in bom_encodings if body.startswith(marker)),
            None,
        )
    if charset is None:
        body_text = body.decode("utf-8", errors="replace")
    else:
        try:
            body_text = body.decode(charset)
        except LookupError as exc:
            raise UnsupportedCharacterEncoding(
                "Unsupported request body character encoding."
            ) from exc
    inspected = _decode_payload(f"{path}\n{header_text}\n{body_text}")

    matches: list[Rule] = []
    for rule in rules:
        if rule.pattern.search(inspected):
            matches.append(rule)

    score = sum(r.weight for r in matches)
    blocked = score >= block_threshold
    return InspectionResult(
        blocked=blocked,
        rule_ids=tuple(r.id for r in matches),
        rule_names=tuple(r.name for r in matches),
        score=score,
        reason=", ".join(r.name for r in matches) or "no rule matched",
    )


def inspect_request(path: str, headers: dict[str, str], body: bytes) -> str | None:
    """Backward-compatible wrapper. Returns the joined rule names or None."""
    result = inspect_full(path, headers, body)
    return result.reason if result.blocked else None


def _decode_request_body(body: bytes, content_encodings: list[str]) -> bytes:
    if len(content_encodings) > 1:
        raise UnsupportedContentEncoding("Multiple Content-Encoding headers are unsupported.")
    if not content_encodings or content_encodings[0].strip().lower() in {"", "identity"}:
        return body

    encoding = content_encodings[0].strip().lower()
    if "," in encoding or encoding not in {"gzip", "deflate"}:
        raise UnsupportedContentEncoding("Unsupported Content-Encoding.")

    window_bits = (
        zlib.MAX_WBITS | 16
        if encoding == "gzip"
        else zlib.MAX_WBITS
    )
    try:
        decoder = zlib.decompressobj(window_bits)
        decoded = decoder.decompress(body, MAX_REQUEST_BODY + 1)
    except zlib.error as exc:
        raise ValueError("Invalid compressed request body.") from exc

    if len(decoded) > MAX_REQUEST_BODY or decoder.unconsumed_tail:
        raise RequestBodyTooLarge("Decoded request body exceeds the 1 MiB limit.")
    if not decoder.eof or decoder.unused_data:
        raise ValueError("Invalid compressed request body.")
    return decoded


# --------------------------------------------------------------------------- #
# Server internals
# --------------------------------------------------------------------------- #
_HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
}

_SUPPORTED_METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")


class _ThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 128


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, address: str) -> None:
        super().__init__(host=host, port=port, timeout=UPSTREAM_TIMEOUT_SECONDS)
        self._pinned_address = address

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._pinned_address, self.port),
            self.timeout,
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        host: str,
        port: int,
        address: str,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(
            host=host,
            port=port,
            timeout=UPSTREAM_TIMEOUT_SECONDS,
            context=context,
        )
        self._pinned_address = address
        self._ssl_context = context

    def connect(self) -> None:
        sock = socket.create_connection(
            (self._pinned_address, self.port),
            self.timeout,
        )
        self.sock = self._ssl_context.wrap_socket(sock, server_hostname=self.host)


# --------------------------------------------------------------------------- #
# Thread-safe stats
# --------------------------------------------------------------------------- #
class _Stats:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.total = 0
        self.inspected = 0
        self.allowed = 0
        self.blocked = 0
        self.by_rule: dict[str, int] = defaultdict(int)
        self.top_clients: dict[str, int] = defaultdict(int)
        self.started_at = time.time()

    def record(
        self,
        action: str,
        client: str,
        rule_ids: Iterable[str],
        *,
        inspected: bool = False,
    ) -> None:
        with self._lock:
            self.total += 1
            if inspected:
                self.inspected += 1
            if action == "BLOCKED":
                self.blocked += 1
            else:
                self.allowed += 1
            self.top_clients[client] += 1
            for rid in rule_ids:
                self.by_rule[rid] += 1

    def snapshot(self) -> StatsSnapshot:
        with self._lock:
            return {
                "total": self.total,
                "inspected": self.inspected,
                "allowed": self.allowed,
                "blocked": self.blocked,
                "block_ratio": (self.blocked / self.total) if self.total else 0.0,
                "by_rule": dict(self.by_rule),
                "top_clients": sorted(
                    self.top_clients.items(), key=lambda kv: kv[1], reverse=True
                )[:10],
                "uptime_seconds": round(time.time() - self.started_at, 1),
            }


# --------------------------------------------------------------------------- #
# Rate limiter
# --------------------------------------------------------------------------- #
class _RateLimiter:
    def __init__(self, window: int, limit: int) -> None:
        self.window = window
        self.limit = limit
        self._lock = threading.Lock()
        self._buckets: dict[str, deque[float]] = defaultdict(deque)

    def hit(self, client: str) -> bool:
        """Return True if the client has exceeded its quota."""
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            bucket = self._buckets[client]
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            bucket.append(now)
            return len(bucket) > self.limit


# --------------------------------------------------------------------------- #
# The proxy
# --------------------------------------------------------------------------- #
class WAFProxy:
    def __init__(
        self,
        backend_url: str,
        port: int,
        event_callback: Callable[[FirewallEvent], None],
        *,
        allowlist_ips: Iterable[str] = (),
        blocklist_ips: Iterable[str] = (),
        allowlist_paths: Iterable[re.Pattern[str]] = (),
        rate_limit_window_seconds: int = RATE_LIMIT_WINDOW_SECONDS,
        rate_limit_max_requests: int = RATE_LIMIT_MAX_REQUESTS,
        allowed_hosts: Iterable[str] = (),
        tls_certfile: str | None = None,
        tls_keyfile: str | None = None,
    ) -> None:
        backend = urlsplit(backend_url)
        if backend.scheme not in {"http", "https"} or not backend.hostname:
            raise ValueError("Backend URL must be a valid http:// or https:// URL.")
        try:
            backend.port
        except ValueError as exc:
            raise ValueError("Backend URL contains an invalid port.") from exc
        if backend.username is not None or backend.password is not None:
            raise ValueError("Backend URL must not contain embedded credentials.")
        if backend.query or backend.fragment:
            raise ValueError("Backend URL cannot include a query string or fragment.")
        if (tls_certfile is None) != (tls_keyfile is None):
            raise ValueError("Both TLS certificate and private key paths are required.")
        if not 0 <= port <= 65535:
            raise ValueError("Listen port must be between 0 and 65535.")
        if (
            type(rate_limit_window_seconds) is not int
            or not 1 <= rate_limit_window_seconds <= 3600
        ):
            raise ValueError("Rate-limit window must be from 1 to 3600 seconds.")
        if (
            type(rate_limit_max_requests) is not int
            or not 1 <= rate_limit_max_requests <= 1_000_000
        ):
            raise ValueError("Rate limit must be from 1 to 1000000 requests.")

        self.backend_url = backend_url.rstrip("/")
        self._backend_scheme = backend.scheme
        self._backend_host = backend.hostname
        self._backend_port = backend.port or (443 if backend.scheme == "https" else 80)
        self._backend_path = backend.path.rstrip("/")
        self._backend_authority = backend.netloc
        self._allowed_hosts = {
            host.strip().rstrip(".").lower()
            for host in allowed_hosts
            if isinstance(host, str) and host.strip()
        }
        self._allowed_hosts.add(self._backend_host.rstrip(".").lower())
        self._backend_addresses = self._resolve_backend_addresses(
            self._backend_host,
            self._backend_port,
        )
        self.port = port
        self._tls_certfile = tls_certfile
        self._tls_keyfile = tls_keyfile
        self._event_callback = event_callback
        self._server: _ThreadingHTTPServer | None = None
        self._server_thread: threading.Thread | None = None

        self._stats = _Stats()
        self._rate_limiter = _RateLimiter(
            rate_limit_window_seconds,
            rate_limit_max_requests,
        )

        self._configuration_lock = threading.RLock()
        self._allowlist_ips = self._normalise_ip_set(allowlist_ips)
        self._blocklist_ips = self._normalise_ip_set(blocklist_ips)
        self._allowlist_paths = tuple(allowlist_paths)
        self._inspection_rules = RULES
        self._block_threshold = BLOCK_THRESHOLD

    @staticmethod
    def _resolve_backend_addresses(host: str, port: int) -> tuple[str, ...]:
        try:
            results = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise ValueError(f"Backend host could not be resolved: {host}") from exc

        addresses: list[str] = []
        for result in results:
            address_value = result[4][0]
            if not isinstance(address_value, str):
                raise ValueError("Backend resolver returned a non-text IP address.")
            address = address_value
            try:
                ip = ipaddress.ip_address(address)
            except ValueError as exc:
                raise ValueError("Backend resolved to an invalid IP address.") from exc
            if (
                ip.is_unspecified
                or ip.is_multicast
                or ip.is_link_local
                or ip.is_reserved
                or not (ip.is_global or ip.is_private or ip.is_loopback)
            ):
                raise ValueError(
                    f"Backend host resolves to a prohibited destination: {ip}"
                )
            if address not in addresses:
                addresses.append(address)
        if not addresses:
            raise ValueError(f"Backend host has no usable address: {host}")
        return tuple(addresses)

    def configure_rules(
        self,
        enabled_rule_ids: Iterable[str],
        weights: Mapping[str, int],
        block_threshold: int,
        custom_rules: Iterable[tuple[str, str]] = (),
    ) -> None:
        known_ids = {rule.id for rule in RULES}
        enabled = frozenset(enabled_rule_ids)
        if not enabled:
            raise ValueError("At least one inspection rule must remain enabled.")
        if enabled - known_ids:
            raise ValueError("Configuration contains an unknown rule ID.")
        if weights.keys() - known_ids:
            raise ValueError("Weights contain an unknown rule ID.")
        if type(block_threshold) is not int or not 1 <= block_threshold <= 100:
            raise ValueError("Block threshold must be an integer from 1 to 100.")

        normalized_weights: dict[str, int] = {}
        for rule in RULES:
            weight = weights.get(rule.id, rule.weight)
            if type(weight) is not int or not 1 <= weight <= 100:
                raise ValueError(f"Weight for {rule.id} must be an integer from 1 to 100.")
            normalized_weights[rule.id] = weight

        inspection_rules = tuple(
            replace(rule, weight=normalized_weights[rule.id])
            for rule in RULES
            if rule.id in enabled
        )
        custom_inspection_rules: list[Rule] = []
        custom_values = tuple(custom_rules)
        if len(custom_values) > 20:
            raise ValueError("At most 20 custom rules may be configured.")
        for index, value in enumerate(custom_values, start=1):
            if (
                not isinstance(value, tuple)
                or len(value) != 2
                or not all(isinstance(part, str) for part in value)
            ):
                raise ValueError("Custom rules must be (name, literal) string pairs.")
            name, literal = (part.strip() for part in value)
            if not name or len(name) > 80 or not literal or len(literal) > 200:
                raise ValueError("Custom rule names and literals must be non-empty and bounded.")
            custom_inspection_rules.append(
                Rule(
                    f"CUSTOM-{index:02d}",
                    name,
                    5,
                    re.compile(re.escape(literal), re.IGNORECASE | re.DOTALL),
                )
            )
        with self._configuration_lock:
            self._inspection_rules = (*inspection_rules, *custom_inspection_rules)
            self._block_threshold = block_threshold

    def configure_access_lists(
        self,
        allowlist_ips: Iterable[str],
        blocklist_ips: Iterable[str],
        allowlist_paths: Iterable[re.Pattern[str]],
    ) -> None:
        normalized_allowlist = self._validated_ip_set(allowlist_ips)
        normalized_blocklist = self._validated_ip_set(blocklist_ips)
        path_patterns = tuple(allowlist_paths)
        if any(not isinstance(pattern, re.Pattern) for pattern in path_patterns):
            raise ValueError("Path bypass entries must be compiled regular expressions.")

        with self._configuration_lock:
            self._allowlist_ips = normalized_allowlist
            self._blocklist_ips = normalized_blocklist
            self._allowlist_paths = path_patterns

    def configure_rate_limit(self, window_seconds: int, maximum_requests: int) -> None:
        if type(window_seconds) is not int or not 1 <= window_seconds <= 3600:
            raise ValueError("Rate-limit window must be from 1 to 3600 seconds.")
        if type(maximum_requests) is not int or not 1 <= maximum_requests <= 1_000_000:
            raise ValueError("Rate limit must be from 1 to 1000000 requests.")
        with self._configuration_lock:
            self._rate_limiter = _RateLimiter(window_seconds, maximum_requests)

    def configure_policy(
        self,
        enabled_rule_ids: Iterable[str],
        weights: Mapping[str, int],
        block_threshold: int,
        allowlist_ips: Iterable[str],
        blocklist_ips: Iterable[str],
        allowlist_paths: Iterable[re.Pattern[str]],
        rate_limit_window_seconds: int,
        rate_limit_max_requests: int,
        custom_rules: Iterable[tuple[str, str]] = (),
    ) -> None:
        with self._configuration_lock:
            previous_policy = (
                self._inspection_rules,
                self._block_threshold,
                self._allowlist_ips,
                self._blocklist_ips,
                self._allowlist_paths,
                self._rate_limiter,
            )
            try:
                self.configure_rules(
                    enabled_rule_ids,
                    weights,
                    block_threshold,
                    custom_rules,
                )
                self.configure_access_lists(
                    allowlist_ips,
                    blocklist_ips,
                    allowlist_paths,
                )
                self.configure_rate_limit(
                    rate_limit_window_seconds,
                    rate_limit_max_requests,
                )
            except (TypeError, ValueError):
                (
                    self._inspection_rules,
                    self._block_threshold,
                    self._allowlist_ips,
                    self._blocklist_ips,
                    self._allowlist_paths,
                    self._rate_limiter,
                ) = previous_policy
                raise

    # -- lifecycle -------------------------------------------------------- #
    def start(self) -> None:
        if self._server is not None:
            raise RuntimeError("Firewall is already running.")

        proxy = self

        class RequestHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = "RIZVI-WAF"
            sys_version = ""

            # route every supported method through one handler
            def do_GET(self): self._handle_request()
            def do_HEAD(self): self._handle_request()
            def do_POST(self): self._handle_request()
            def do_PUT(self): self._handle_request()
            def do_PATCH(self): self._handle_request()
            def do_DELETE(self): self._handle_request()
            def do_OPTIONS(self): self._handle_request()
            def do_TRACE(self): self._handle_request()

            # ---------- main pipeline ---------- #
            def _handle_request(self) -> None:
                started = time.monotonic()
                path_for_log = self.path.split("?", 1)[0][:240] or "/"
                client = self.client_address[0]
                with proxy._configuration_lock:
                    blocklist_ips = proxy._blocklist_ips
                    allowlist_ips = proxy._allowlist_ips
                    allowlist_paths = proxy._allowlist_paths
                    inspection_rules = proxy._inspection_rules
                    block_threshold = proxy._block_threshold
                    rate_limiter = proxy._rate_limiter

                # Each listener is permanently mapped to one backend. The Host
                # header is checked for consistency, never used for routing.
                host_values = self.headers.get_all("Host", [])
                if len(host_values) != 1 or not host_values[0].strip():
                    self._respond_error(400, "Exactly one Host header is required.")
                    proxy._emit(
                        self,
                        "BLOCKED",
                        400,
                        "Invalid Host header",
                        path_for_log,
                        rule_ids=("HOST",),
                        score=100,
                        severity="BLOCK",
                    )
                    return
                host_header = host_values[0]
                try:
                    parsed_host = urlsplit(f"//{host_header}")
                    request_host = parsed_host.hostname
                    request_host_port = parsed_host.port
                    if (
                        parsed_host.username is not None
                        or parsed_host.password is not None
                        or parsed_host.path
                        or parsed_host.query
                        or parsed_host.fragment
                    ):
                        request_host = None
                except ValueError:
                    request_host = None
                    request_host_port = None
                allowed_hosts = proxy._allowed_hosts | {
                    "localhost",
                    "127.0.0.1",
                }
                if (
                    request_host is None
                    or request_host.rstrip(".").lower() not in allowed_hosts
                    or (
                        request_host_port is not None
                        and request_host_port != proxy.port
                    )
                ):
                    self._respond_error(421, "Host is not registered for this listener.")
                    proxy._emit(
                        self,
                        "BLOCKED",
                        421,
                        "Unregistered Host header",
                        path_for_log,
                        rule_ids=("HOST",),
                        score=100,
                        severity="BLOCK",
                    )
                    return

                # -- IP blocklist --
                if proxy._ip_in(client, blocklist_ips):
                    self._respond_error(403, "Client IP blocked by RIZVI WAF.")
                    proxy._emit(self, "BLOCKED", 403, "IP blocklist", path_for_log,
                                rule_ids=("IP-BLOCK",), score=100, severity="BLOCK")
                    return

                # -- method allowlist --
                if self.command not in _SUPPORTED_METHODS or self.command in BLOCKED_METHODS:
                    self._respond_error(405, f"Method {self.command} not allowed.")
                    proxy._emit(self, "BLOCKED", 405, "Method not allowed", path_for_log,
                                rule_ids=("METHOD",), score=100, severity="BLOCK")
                    return

                # -- rate limit --
                if rate_limiter.hit(client):
                    self._respond_error(429, "Too many requests.")
                    proxy._emit(self, "BLOCKED", 429, "Rate limit exceeded", path_for_log,
                                rule_ids=("RATE",), score=100, severity="BLOCK")
                    return

                # -- header sanity --
                header_bytes = sum(len(k) + len(v) for k, v in self.headers.items())
                if header_bytes > MAX_HEADER_BYTES:
                    self._respond_error(431, "Header block too large.")
                    proxy._emit(self, "BLOCKED", 431, "Headers too large", path_for_log,
                                rule_ids=("HDR-SIZE",), score=100, severity="BLOCK")
                    return

                # -- content-length / TE --
                content_lengths = self.headers.get_all("Content-Length", [])
                transfer_encodings = self.headers.get_all("Transfer-Encoding", [])
                if len(content_lengths) > 1:
                    self._respond_error(400, "Multiple Content-Length headers are not allowed.")
                    proxy._emit(
                        self,
                        "BLOCKED",
                        400,
                        "Ambiguous Content-Length",
                        path_for_log,
                        rule_ids=("LEN",),
                        score=100,
                        severity="BLOCK",
                    )
                    return
                try:
                    content_length_text = content_lengths[0] if content_lengths else "0"
                    if not content_length_text.isascii() or not content_length_text.isdecimal():
                        raise ValueError("Content-Length must be an unsigned decimal integer.")
                    content_length = int(content_length_text)
                except ValueError:
                    self._respond_error(400, "Invalid Content-Length.")
                    proxy._emit(self, "BLOCKED", 400, "Invalid Content-Length", path_for_log,
                                rule_ids=("LEN",), score=100, severity="BLOCK")
                    return
                if content_length < 0 or content_length > MAX_REQUEST_BODY:
                    self._respond_error(413, "Request body exceeds the 1 MiB limit.")
                    proxy._emit(self, "BLOCKED", 413, "Body too large", path_for_log,
                                rule_ids=("BODY-SIZE",), score=100, severity="BLOCK")
                    return
                if transfer_encodings:
                    self._respond_error(501, "Chunked bodies are not supported.")
                    proxy._emit(self, "BLOCKED", 501, "Unsupported Transfer-Encoding",
                                path_for_log, rule_ids=("TE",), score=100, severity="BLOCK")
                    return

                # -- path form --
                if not self.path.startswith("/") or self.path.startswith("//"):
                    self._respond_error(400, "Request target must use origin-form.")
                    proxy._emit(self, "BLOCKED", 400, "Invalid request target", path_for_log,
                                rule_ids=("PATH-FORM",), score=100, severity="BLOCK")
                    return

                body = self.rfile.read(content_length) if content_length else b""
                headers_dict = {k: v for k, v in self.headers.items()}
                content_type = self.headers.get("Content-Type", "")

                # -- allowlist bypass --
                bypass = (
                    proxy._ip_in(client, allowlist_ips)
                    or any(p.search(path_for_log) for p in allowlist_paths)
                )
                inspection_performed = not bypass

                if not bypass:
                    try:
                        inspection_body = _decode_request_body(
                            body,
                            self.headers.get_all("Content-Encoding", []),
                        )
                    except UnsupportedContentEncoding:
                        self._respond_error(415, "Unsupported Content-Encoding.")
                        proxy._emit(
                            self,
                            "BLOCKED",
                            415,
                            "Unsupported Content-Encoding",
                            path_for_log,
                            rule_ids=("CONTENT-ENCODING",),
                            score=100,
                            severity="BLOCK",
                        )
                        return
                    except RequestBodyTooLarge:
                        self._respond_error(413, "Decoded request body exceeds the 1 MiB limit.")
                        proxy._emit(
                            self,
                            "BLOCKED",
                            413,
                            "Decoded body too large",
                            path_for_log,
                            rule_ids=("BODY-SIZE",),
                            score=100,
                            severity="BLOCK",
                        )
                        return
                    except ValueError:
                        self._respond_error(400, "Invalid compressed request body.")
                        proxy._emit(
                            self,
                            "BLOCKED",
                            400,
                            "Invalid compressed request body",
                            path_for_log,
                            rule_ids=("CONTENT-ENCODING",),
                            score=100,
                            severity="BLOCK",
                        )
                        return
                    try:
                        result = inspect_full(
                            self.path,
                            headers_dict,
                            inspection_body,
                            content_type,
                            rules=inspection_rules,
                            block_threshold=block_threshold,
                        )
                    except UnsupportedCharacterEncoding:
                        self._respond_error(415, "Unsupported request body character encoding.")
                        proxy._emit(
                            self,
                            "BLOCKED",
                            415,
                            "Unsupported request body character encoding",
                            path_for_log,
                            rule_ids=("CONTENT-CHARSET",),
                            score=100,
                            severity="BLOCK",
                        )
                        return
                    except ValueError:
                        self._respond_error(400, "Invalid request body character encoding.")
                        proxy._emit(
                            self,
                            "BLOCKED",
                            400,
                            "Invalid request body character encoding",
                            path_for_log,
                            rule_ids=("CONTENT-CHARSET",),
                            score=100,
                            severity="BLOCK",
                        )
                        return
                    if result.blocked:
                        self._respond_error(403, "Request blocked by RIZVI WAF.")
                        proxy._emit(
                            self, "BLOCKED", 403, result.reason, path_for_log,
                            rule_ids=result.rule_ids, score=result.score, severity="BLOCK",
                            inspected=True,
                        )
                        return

                # The local health route is inspected and rate-limited but
                # reveals no counters and is never forwarded to the backend.
                if path_for_log == HEALTH_PATH:
                    if self.command not in {"GET", "HEAD"}:
                        self._respond_error(405, "Health endpoint supports GET and HEAD only.")
                        proxy._emit(
                            self,
                            "BLOCKED",
                            405,
                            "Health endpoint method not allowed",
                            path_for_log,
                            rule_ids=("METHOD",),
                            score=100,
                            severity="BLOCK",
                            inspected=inspection_performed,
                        )
                        return
                    self._respond_json(200, {"status": "ok"})
                    proxy._emit(
                        self,
                        "ALLOWED",
                        200,
                        "Health check",
                        path_for_log,
                        inspected=inspection_performed,
                    )
                    return

                # -- forward upstream --
                target_path = f"{proxy._backend_path}{self.path}"
                if not target_path:
                    target_path = "/"
                connection_tokens = {
                    token.strip().lower()
                    for token in self.headers.get("Connection", "").split(",")
                    if token.strip()
                }
                forward_headers = {
                    k: v for k, v in self.headers.items()
                    if k.lower() not in _HOP_BY_HOP_HEADERS
                    and k.lower() not in connection_tokens
                    and k.lower() not in {"host", "content-length"}
                }
                forward_headers["X-Forwarded-For"] = client
                forward_headers["Host"] = proxy._backend_authority
                forward_headers["X-Forwarded-Proto"] = (
                    "https" if proxy._tls_certfile else "http"
                )

                status: int | None = None
                response_headers: list[tuple[str, str]] = []
                response_body = b""
                upstream_error: BaseException | None = None
                tls_context = (
                    ssl.create_default_context()
                    if proxy._backend_scheme == "https"
                    else None
                )
                for address in proxy._backend_addresses:
                    if tls_context is not None:
                        connection: http.client.HTTPConnection = _PinnedHTTPSConnection(
                            proxy._backend_host,
                            proxy._backend_port,
                            address,
                            tls_context,
                        )
                    else:
                        connection = _PinnedHTTPConnection(
                            proxy._backend_host,
                            proxy._backend_port,
                            address,
                        )
                    try:
                        connection.request(
                            self.command,
                            target_path,
                            body=body if self.command not in {"GET", "HEAD"} else None,
                            headers=forward_headers,
                        )
                        response = connection.getresponse()
                        status = response.status
                        response_headers = response.getheaders()
                        response_body = response.read(MAX_UPSTREAM_RESPONSE_BYTES + 1)
                        upstream_error = None
                        break
                    except (http.client.HTTPException, TimeoutError, OSError) as exc:
                        upstream_error = exc
                    finally:
                        connection.close()

                if upstream_error is not None or status is None:
                    self._respond_error(502, "Backend is unavailable.")
                    proxy._emit(
                        self, "ALLOWED", 502,
                        f"Backend error: {type(upstream_error).__name__}",
                        path_for_log,
                        severity="WARN",
                        inspected=inspection_performed,
                    )
                    return

                if len(response_body) > MAX_UPSTREAM_RESPONSE_BYTES:
                    self._respond_error(502, "Backend response exceeds the 5 MB limit.")
                    proxy._emit(self, "ALLOWED", 502, "Backend response too large",
                                path_for_log,
                                severity="WARN",
                                inspected=inspection_performed)
                    return

                # -- optional response inspection --
                if INSPECT_RESPONSES:
                    body_text = response_body.decode("utf-8", errors="replace")
                    leaks = []
                    if re.search(r"<script\b", body_text, re.IGNORECASE):
                        leaks.append("script tag reflection")
                    if re.search(r"(?:Traceback \(most recent call last\)|"
                                 r"at [\w.$]+\([\w.]+\.java:\d+\))", body_text):
                        leaks.append("stack trace leak")
                    if leaks:
                        proxy._emit(
                            self, "ALLOWED", status,
                            "Response inspection: " + ", ".join(leaks),
                            path_for_log, severity="WARN",
                        )

                # -- relay to client --
                self.send_response(status)
                for key, value in response_headers:
                    if key.lower() not in _HOP_BY_HOP_HEADERS and key.lower() != "content-length":
                        self.send_header(key, value)
                self.send_header("Content-Length", str(len(response_body)))
                self.send_header("Connection", "close")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(response_body)
                self.close_connection = True

                elapsed_ms = int((time.monotonic() - started) * 1000)
                proxy._emit(
                    self, "ALLOWED", status,
                    f"Forwarded in {elapsed_ms} ms",
                    path_for_log,
                    inspected=inspection_performed,
                )

            # ---------- helpers ---------- #
            def _respond_error(self, status: int, message: str) -> None:
                payload = (message + "\n").encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Connection", "close")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)
                self.close_connection = True

            def _respond_json(
                self,
                status: int,
                payload: Mapping[str, object],
            ) -> None:
                body = json.dumps(payload, indent=2).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)
                self.close_connection = True

            def log_message(self, format: str, *args: object) -> None:
                _ = format, args

        tls_context: ssl.SSLContext | None = None
        if self._tls_certfile is not None and self._tls_keyfile is not None:
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_context.load_cert_chain(self._tls_certfile, self._tls_keyfile)
        server = _ThreadingHTTPServer(("127.0.0.1", self.port), RequestHandler)
        if tls_context is not None:
            try:
                server.socket = tls_context.wrap_socket(server.socket, server_side=True)
            except OSError:
                server.server_close()
                raise
        self._server = server
        self.port = server.server_address[1]
        self._server_thread = threading.Thread(
            target=self._server.serve_forever,
            name="rizvi-waf-proxy",
            daemon=True,
        )
        try:
            self._server_thread.start()
        except (OSError, RuntimeError):
            server.server_close()
            self._server = None
            self._server_thread = None
            raise

    @property
    def is_running(self) -> bool:
        return (
            self._server is not None
            and self._server_thread is not None
            and self._server_thread.is_alive()
        )

    def stop(self) -> None:
        server = self._server
        if server is None:
            return
        server.shutdown()
        server.server_close()
        if self._server_thread is not None:
            self._server_thread.join(timeout=SHUTDOWN_GRACE_SECONDS)
        self._server = None
        self._server_thread = None

    def stats(self) -> StatsSnapshot:
        return self._stats.snapshot()

    # -- internals -------------------------------------------------------- #
    @staticmethod
    def _normalise_ip_set(values: Iterable[str]) -> tuple:
        out = []
        for raw in values:
            try:
                out.append(ipaddress.ip_network(raw, strict=False))
            except ValueError:
                continue
        return tuple(out)

    @staticmethod
    def _validated_ip_set(values: Iterable[str]) -> tuple:
        out = []
        seen = set()
        for value in values:
            if not isinstance(value, str) or not value.strip():
                raise ValueError("IP entries must be non-empty IPv4, IPv6, or CIDR values.")
            try:
                network = ipaddress.ip_network(value.strip(), strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid IP or CIDR entry: {value!r}") from exc
            if network not in seen:
                out.append(network)
                seen.add(network)
        return tuple(out)

    @staticmethod
    def _ip_in(addr: str, networks: tuple) -> bool:
        if not networks:
            return False
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        return any(ip in net for net in networks)

    def _emit(
        self,
        handler: BaseHTTPRequestHandler,
        action: str,
        status: int,
        detail: str,
        path: str,
        *,
        rule_ids: Iterable[str] = (),
        score: int = 0,
        severity: str = "INFO",
        inspected: bool = False,
    ) -> None:
        rule_id_values = tuple(rule_ids)
        self._stats.record(
            action,
            handler.client_address[0],
            rule_id_values,
            inspected=inspected,
        )
        event = FirewallEvent(
            timestamp=datetime.now().strftime("%H:%M:%S"),
            action=action,
            method=handler.command,
            path=path or "/",
            client=handler.client_address[0],
            status=status,
            detail=detail,
            severity=severity,
            rule_id=",".join(rule_id_values),
            score=score,
            inspected=inspected,
        )
        self._event_callback(event)