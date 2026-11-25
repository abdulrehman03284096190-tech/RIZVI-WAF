from __future__ import annotations

import http.client
import json
import socket
import ssl
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote

from applications import ApplicationRegistry
from waf import RULES, FirewallEvent, WAFProxy


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


class ApplicationRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        root = Path(self.temporary_directory.name)
        self.events: list[tuple[str, object]] = []
        self.registry = ApplicationRegistry(
            event_callback=lambda app_id, event: self.events.append((app_id, event)),
            log_directory=root / "events",
            audit_path=root / "audit.jsonl",
        )
        self.backend_hits = {"first": 0, "second": 0}
        self.backends: list[ThreadingHTTPServer] = []
        self.backend_threads: list[threading.Thread] = []
        self.first_backend = self._start_backend("first")
        self.second_backend = self._start_backend("second")

    def tearDown(self) -> None:
        try:
            self.registry.shutdown()
        finally:
            for backend in self.backends:
                backend.shutdown()
                backend.server_close()
            for thread in self.backend_threads:
                thread.join(timeout=2)
            self.temporary_directory.cleanup()

    def _start_backend(self, label: str) -> ThreadingHTTPServer:
        test_case = self

        class BackendHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                test_case.backend_hits[label] += 1
                body = label.encode("ascii")
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                _ = format, args

        backend = ThreadingHTTPServer(("127.0.0.1", 0), BackendHandler)
        thread = threading.Thread(target=backend.serve_forever, daemon=True)
        thread.start()
        self.backends.append(backend)
        self.backend_threads.append(thread)
        return backend

    def _register(self, name: str, backend: ThreadingHTTPServer) -> str:
        spec = self.registry.add_application(
            {
                "name": name,
                "backend_url": f"http://127.0.0.1:{backend.server_address[1]}",
                "listen_port": _free_port(),
                "authorized": True,
            },
            confirmed=True,
        )
        return spec.id

    def _request(self, port: int, path: str = "/") -> tuple[int, bytes]:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def _wait_for_events(self, app_id: str, expected: int) -> None:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if len(self.registry.application_events(app_id)) >= expected:
                return
            time.sleep(0.01)
        self.fail(f"Timed out waiting for {expected} events for {app_id}")

    def test_multiple_applications_route_and_keep_security_state_isolated(self) -> None:
        first_id = self._register("First app", self.first_backend)
        second_id = self._register("Second app", self.second_backend)
        first = next(
            item for item in self.registry.list_applications() if item["id"] == first_id
        )
        second = next(
            item for item in self.registry.list_applications() if item["id"] == second_id
        )

        self.assertEqual(first["protection_status"], "Stopped")
        self.assertEqual(second["protection_status"], "Stopped")
        self.registry.update_security(
            first_id,
            {"block_threshold": 100},
            confirmed=True,
        )
        first_port = self.registry.start_protection(first_id, confirmed=True)
        second_port = self.registry.start_protection(second_id, confirmed=True)
        self.assertEqual(
            self.registry.protection_status(first_id),
            "Listening — awaiting inspected traffic",
        )
        self.assertEqual(
            self.registry.protection_status(second_id),
            "Listening — awaiting inspected traffic",
        )

        attack = "/search?q=" + quote("<script>alert(1)</script>")
        first_status, first_body = self._request(first_port, attack)
        second_status, second_body = self._request(second_port, attack)
        self._wait_for_events(first_id, 1)
        self._wait_for_events(second_id, 1)
        self.assertEqual((first_status, first_body), (200, b"first"))
        self.assertEqual(second_status, 403)
        self.assertIn(b"blocked", second_body.lower())
        self.assertEqual(self.backend_hits, {"first": 1, "second": 0})

        first_events = self.registry.application_events(first_id)
        second_events = self.registry.application_events(second_id)
        self.assertEqual(len(first_events), 1)
        self.assertEqual(first_events[0]["action"], "ALLOWED")
        self.assertEqual(len(second_events), 1)
        self.assertEqual(second_events[0]["action"], "BLOCKED")
        self.assertEqual(self.registry.protection_status(first_id), "Protected")
        self.assertEqual(self.registry.protection_status(second_id), "Protected")
        self.assertEqual(self.registry.application_events(first_id, attacks_only=True), [])
        self.assertEqual(len(self.registry.application_events(second_id, attacks_only=True)), 1)

    def test_custom_literal_rules_are_applied_by_the_selected_app_only(self) -> None:
        first_id = self._register("First app", self.first_backend)
        second_id = self._register("Second app", self.second_backend)
        self.registry.update_security(
            first_id,
            {
                "enabled_rule_ids": [rule.id for rule in RULES],
                "custom_rules": [{"name": "Private marker", "pattern": "x-private-marker"}],
            },
            confirmed=True,
        )
        first_port = self.registry.start_protection(first_id, confirmed=True)
        second_port = self.registry.start_protection(second_id, confirmed=True)
        path = "/search?q=" + quote("x-private-marker")

        first_status, _ = self._request(first_port, path)
        second_status, _ = self._request(second_port, path)
        self._wait_for_events(first_id, 1)
        self._wait_for_events(second_id, 1)

        self.assertEqual(first_status, 403)
        self.assertEqual(second_status, 200)
        self.assertEqual(self.backend_hits, {"first": 0, "second": 1})

    def test_rate_limits_are_isolated_per_application(self) -> None:
        first_id = self._register("Limited app", self.first_backend)
        second_id = self._register("Normal app", self.second_backend)
        first_port = self.registry.start_protection(first_id, confirmed=True)
        second_port = self.registry.start_protection(second_id, confirmed=True)
        self.registry.update_security(
            first_id,
            {
                "rate_limit_window_seconds": 60,
                "rate_limit_max_requests": 1,
            },
            confirmed=True,
        )

        first_statuses = [
            self._request(first_port, "/one")[0],
            self._request(first_port, "/two")[0],
        ]
        second_statuses = [
            self._request(second_port, "/one")[0],
            self._request(second_port, "/two")[0],
        ]
        self._wait_for_events(first_id, 2)
        self._wait_for_events(second_id, 2)

        self.assertEqual(first_statuses, [200, 429])
        self.assertEqual(second_statuses, [200, 200])
        self.assertEqual(self.backend_hits, {"first": 1, "second": 2})

    def test_reverse_proxy_blocks_sql_injection_and_xss_before_backend(self) -> None:
        app_id = self._register("Attack test app", self.first_backend)
        port = self.registry.start_protection(app_id, confirmed=True)
        payloads = (
            "/search?q=" + quote("' OR 1=1 -- "),
            "/search?q=" + quote("<script>alert(1)</script>"),
        )

        statuses = [self._request(port, payload)[0] for payload in payloads]
        self._wait_for_events(app_id, 2)

        self.assertEqual(statuses, [403, 403])
        self.assertEqual(self.backend_hits["first"], 0)
        attacks = self.registry.application_events(app_id, attacks_only=True)
        self.assertEqual(len(attacks), 2)
        self.assertIn("SQLI-02", str(attacks[0]["rule_id"]))
        self.assertIn("XSS-01", str(attacks[1]["rule_id"]))

    def test_only_registered_hostnames_and_listener_ports_are_accepted(self) -> None:
        spec = self.registry.add_application(
            {
                "name": "Host-mapped app",
                "backend_url": (
                    f"http://127.0.0.1:{self.first_backend.server_address[1]}"
                ),
                "hostnames": ["shop.example.test"],
                "listen_port": _free_port(),
                "authorized": True,
            },
            confirmed=True,
        )
        port = self.registry.start_protection(spec.id, confirmed=True)

        def request(host: str) -> int:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            try:
                connection.request("GET", "/", headers={"Host": host})
                response = connection.getresponse()
                response.read()
                return response.status
            finally:
                connection.close()

        self.assertEqual(request(f"shop.example.test:{port}"), 200)
        self.assertEqual(request(f"unregistered.example.test:{port}"), 421)
        self.assertEqual(request(f"shop.example.test:{port + 1}"), 421)
        self.assertEqual(self.backend_hits["first"], 1)

    def test_confirmation_authorization_and_port_conflicts_are_enforced(self) -> None:
        with self.assertRaises(PermissionError):
            self.registry.add_application(
                {
                    "name": "Unconfirmed",
                    "backend_url": "http://127.0.0.1:8000",
                    "listen_port": _free_port(),
                    "authorized": True,
                }
            )
        with self.assertRaises(PermissionError):
            self.registry.add_application(
                {
                    "name": "Not authorized",
                    "backend_url": "http://127.0.0.1:8000",
                    "listen_port": _free_port(),
                    "authorized": False,
                },
                confirmed=True,
            )

        port = _free_port()
        first_spec = self.registry.add_application(
            {
                "name": "First",
                "backend_url": "http://127.0.0.1:8000",
                "listen_port": port,
                "authorized": True,
            },
            confirmed=True,
        )
        with self.assertRaisesRegex(ValueError, "already assigned"):
            self.registry.add_application(
                {
                    "name": "Second",
                    "backend_url": "http://127.0.0.1:8001",
                    "listen_port": port,
                    "authorized": True,
                },
                confirmed=True,
            )
        with self.assertRaisesRegex(ValueError, "ID .* already registered"):
            self.registry.add_application(
                {
                    "id": first_spec.id,
                    "name": "Duplicate ID",
                    "backend_url": "http://127.0.0.1:8001",
                    "listen_port": _free_port(),
                    "authorized": True,
                },
                confirmed=True,
            )

        app_id = first_spec.id
        with self.assertRaises(PermissionError):
            self.registry.start_protection(str(app_id))

    def test_backend_failures_and_operating_system_port_conflicts_are_reported(self) -> None:
        unavailable_port = _free_port()
        app_id = self.registry.add_application(
            {
                "name": "Unavailable backend",
                "backend_url": f"http://127.0.0.1:{unavailable_port}",
                "listen_port": _free_port(),
                "authorized": True,
            },
            confirmed=True,
        ).id
        with self.assertRaises(OSError):
            self.registry.test_connection(app_id, confirmed=True)
        unavailable = next(
            app
            for app in self.registry.list_applications()
            if app["id"] == app_id
        )
        self.assertEqual(unavailable["connection_status"], "Unavailable")

        occupied = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
        try:
            conflict_id = self.registry.add_application(
                {
                    "name": "Port conflict",
                    "backend_url": (
                        f"http://127.0.0.1:{self.first_backend.server_address[1]}"
                    ),
                    "listen_port": occupied.server_address[1],
                    "authorized": True,
                },
                confirmed=True,
            ).id
            with self.assertRaises(OSError):
                self.registry.start_protection(conflict_id, confirmed=True)
            self.assertEqual(self.registry.protection_status(conflict_id), "Stopped")
        finally:
            occupied.server_close()

    def test_backend_connection_does_not_claim_waf_protection(self) -> None:
        app_id = self._register("Reachable app", self.first_backend)

        self.assertEqual(
            self.registry.test_connection(app_id, confirmed=True),
            "Reachable",
        )
        application = next(
            item
            for item in self.registry.list_applications()
            if item["id"] == app_id
        )
        self.assertEqual(application["connection_status"], "Reachable")
        self.assertEqual(application["protection_status"], "Stopped")
        self.assertFalse(application["is_protected"])

    def test_https_backend_certificate_failures_are_not_downgraded(self) -> None:
        events = []
        proxy = WAFProxy(
            f"https://127.0.0.1:{self.first_backend.server_address[1]}",
            0,
            events.append,
        )
        proxy.start()
        try:
            status, body = self._request(proxy.port)
            deadline = time.monotonic() + 2
            while not events and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(status, 502)
            self.assertIn(b"Backend is unavailable", body)
            self.assertEqual(self.backend_hits["first"], 0)
            self.assertTrue(events)
            self.assertIn("Backend error:", events[0].detail)
        finally:
            proxy.stop()

    def test_invalid_tls_listener_certificates_fail_before_listen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cert_path = Path(directory) / "missing-cert.pem"
            key_path = Path(directory) / "missing-key.pem"
            proxy = WAFProxy(
                f"http://127.0.0.1:{self.first_backend.server_address[1]}",
                0,
                lambda _event: None,
                tls_certfile=str(cert_path),
                tls_keyfile=str(key_path),
            )
            with self.assertRaises((OSError, ssl.SSLError)):
                proxy.start()
            self.assertFalse(proxy.is_running)

    def test_ssrf_destinations_are_rejected_and_reports_are_application_scoped(self) -> None:
        with self.assertRaisesRegex(ValueError, "prohibited destination"):
            WAFProxy._resolve_backend_addresses("169.254.169.254", 80)

        app_id = self._register("Report app", self.first_backend)
        port = self.registry.start_protection(app_id, confirmed=True)
        self._request(port, "/")
        self._wait_for_events(app_id, 1)
        report_path = Path(self.temporary_directory.name) / "report.json"
        report = self.registry.generate_report(app_id, report_path)
        reloaded = json.loads(report_path.read_text(encoding="utf-8"))
        report_application = report.get("application")
        if not isinstance(report_application, dict):
            self.fail("Report application metadata was not written as an object")
        self.assertEqual(report_application.get("id"), app_id)
        self.assertEqual(reloaded["recorded_event_count"], 1)
        report_stats = reloaded.get("session_statistics")
        if not isinstance(report_stats, dict):
            self.fail("Report statistics were not written as an object")
        self.assertEqual(report_stats.get("inspected"), 1)

        audit_lines = (
            Path(self.temporary_directory.name) / "audit.jsonl"
        ).read_text(encoding="utf-8").splitlines()
        audit_actions = []
        for line in audit_lines:
            entry = json.loads(line)
            if isinstance(entry, dict):
                audit_actions.append(entry.get("action"))
        self.assertIn("start_protection", audit_actions)

    def test_application_configuration_and_event_history_restore_independently(self) -> None:
        app_id = self._register("Persistent app", self.first_backend)
        port = self.registry.start_protection(app_id, confirmed=True)
        self._request(port, "/")
        self._wait_for_events(app_id, 1)

        restored = ApplicationRegistry(
            applications=self.registry.configurations(),
            log_directory=Path(self.temporary_directory.name) / "events",
            audit_path=Path(self.temporary_directory.name) / "audit.jsonl",
        )
        try:
            applications = restored.list_applications()
            self.assertEqual(len(applications), 1)
            self.assertEqual(applications[0]["id"], app_id)
            self.assertEqual(applications[0]["protection_status"], "Stopped")
            self.assertEqual(applications[0]["event_count"], 1)
            self.assertEqual(len(restored.application_events(app_id)), 1)
        finally:
            restored.shutdown()

    def test_corrupt_event_history_is_reported_without_discarding_valid_entries(self) -> None:
        app_id = self._register("Corrupt history app", self.first_backend)
        event_path = Path(self.temporary_directory.name) / "events" / f"{app_id}.jsonl"
        event_path.write_text(
            json.dumps(
                {
                    "application_id": app_id,
                    "action": "BLOCKED",
                    "timestamp": "12:00:00",
                }
            )
            + "\n"
            + "{invalid json\n",
            encoding="utf-8",
        )
        restored = ApplicationRegistry(
            applications=self.registry.configurations(),
            log_directory=Path(self.temporary_directory.name) / "events",
            audit_path=Path(self.temporary_directory.name) / "audit.jsonl",
        )
        try:
            application = restored.list_applications()[0]
            self.assertEqual(application["event_count"], 1)
            self.assertEqual(application["recorded_attack_count"], 1)
            self.assertIn("Invalid event history", application["log_error"])
            self.assertEqual(len(restored.application_events(app_id)), 1)
            quarantined = list(
                (Path(self.temporary_directory.name) / "events").glob(
                    f"{app_id}.jsonl.corrupt-*"
                )
            )
            self.assertEqual(len(quarantined), 1)
            restored._record_event(
                app_id,
                FirewallEvent(
                    "12:00:01",
                    "ALLOWED",
                    "GET",
                    "/after-recovery",
                    "127.0.0.1",
                    200,
                    "test",
                ),
            )
        finally:
            restored.shutdown()
        reloaded = ApplicationRegistry(
            applications=self.registry.configurations(),
            log_directory=Path(self.temporary_directory.name) / "events",
            audit_path=Path(self.temporary_directory.name) / "audit.jsonl",
        )
        try:
            application = reloaded.list_applications()[0]
            self.assertEqual(application["event_count"], 2)
            self.assertEqual(application["log_error"], "")
        finally:
            reloaded.shutdown()

    def test_report_replacement_is_atomic_when_storage_fails(self) -> None:
        app_id = self._register("Atomic report app", self.first_backend)
        report_path = Path(self.temporary_directory.name) / "report.json"
        report_path.write_text("previous report\n", encoding="utf-8")

        with patch("applications.os.replace", side_effect=OSError("disk unavailable")):
            with self.assertRaisesRegex(OSError, "disk unavailable"):
                self.registry.generate_report(app_id, report_path)

        self.assertEqual(report_path.read_text(encoding="utf-8"), "previous report\n")
        self.assertEqual(
            list(Path(self.temporary_directory.name).glob(".report.json.*.tmp")),
            [],
        )


if __name__ == "__main__":
    unittest.main()
