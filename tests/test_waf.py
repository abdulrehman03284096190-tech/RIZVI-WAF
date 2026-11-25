from __future__ import annotations

import gzip
import http.client
import re
import socket
import threading
import unittest
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote

from waf import MAX_REQUEST_BODY, RULES, FirewallEvent, WAFProxy, inspect_request


class InspectionTests(unittest.TestCase):
    def test_allows_normal_request(self) -> None:
        self.assertIsNone(
            inspect_request("/products/42", {"Accept": "application/json"}, b"")
        )

    def test_detects_encoded_script_and_traversal(self) -> None:
        self.assertEqual(
            inspect_request("/search?q=%3Cscript%3E", {}, b""),
            "Script tag",
        )
        self.assertEqual(
            inspect_request("/files/..%2f..%2fsecret", {}, b""),
            "Path traversal",
        )

    def test_detects_sql_pattern_in_body(self) -> None:
        self.assertEqual(
            inspect_request("/login", {}, b"username=' OR 1=1 -- "),
            "SQL injection (tautology), SQL comment / block",
        )


class ProxyIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend_hits = 0
        test_case = self

        class BackendHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                test_case.backend_hits += 1
                payload = b"backend response"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_POST(self) -> None:
                test_case.backend_hits += 1
                payload = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format: str, *args: object) -> None:
                _ = format, args
                return

        self.backend = ThreadingHTTPServer(("127.0.0.1", 0), BackendHandler)
        self.backend_thread = threading.Thread(target=self.backend.serve_forever, daemon=True)
        self.backend_thread.start()
        self.events: list[FirewallEvent] = []
        self.blocked_event = threading.Event()

        def record_event(event: FirewallEvent) -> None:
            self.events.append(event)
            if event.action == "BLOCKED":
                self.blocked_event.set()

        self.proxy = WAFProxy(
            f"http://127.0.0.1:{self.backend.server_address[1]}",
            0,
            record_event,
        )
        self.proxy.start()

    def tearDown(self) -> None:
        self.proxy.stop()
        self.backend.shutdown()
        self.backend.server_close()
        self.backend_thread.join(timeout=2)

    def test_forwards_clean_and_blocks_suspicious_request(self) -> None:
        connection = http.client.HTTPConnection("127.0.0.1", self.proxy.port, timeout=3)
        try:
            connection.request("GET", "/health")
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), b"backend response")
            self.assertEqual(self.backend_hits, 1)

            suspicious_path = "/search?q=" + quote("<script>alert(1)</script>")
            connection.request("GET", suspicious_path)
            blocked = connection.getresponse()
            self.assertEqual(blocked.status, 403)
            blocked.read()
            self.assertEqual(self.backend_hits, 1)
            self.assertTrue(self.blocked_event.wait(timeout=1))
            self.assertTrue(any(event.action == "BLOCKED" for event in self.events))
        finally:
            connection.close()

    def test_compressed_request_bodies_are_inspected_and_safe_bodies_are_forwarded(self) -> None:
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            self.proxy.port,
            timeout=3,
        )
        try:
            for encoding, body in (
                ("gzip", gzip.compress(b"query=normal")),
                ("deflate", zlib.compress(b"query=normal")),
            ):
                connection.request(
                    "POST",
                    "/submit",
                    body=body,
                    headers={
                        "Content-Encoding": encoding,
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                )
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(response.read(), body)

            attack = gzip.compress(b"username=' OR 1=1 -- ")
            connection.request(
                "POST",
                "/login",
                body=attack,
                headers={"Content-Encoding": "gzip"},
            )
            blocked = connection.getresponse()
            self.assertEqual(blocked.status, 403)
            blocked.read()
            self.assertEqual(self.backend_hits, 2)
        finally:
            connection.close()

    def test_invalid_unsupported_and_oversized_encoded_bodies_fail_closed(self) -> None:
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            self.proxy.port,
            timeout=3,
        )
        try:
            cases = (
                ("gzip", b"not a gzip stream", 400),
                ("br", b"encoded data", 415),
                ("gzip", gzip.compress(b"a" * (MAX_REQUEST_BODY + 1)), 413),
            )
            for encoding, body, expected_status in cases:
                connection.request(
                    "POST",
                    "/submit",
                    body=body,
                    headers={"Content-Encoding": encoding},
                )
                response = connection.getresponse()
                self.assertEqual(response.status, expected_status)
                response.read()
            self.assertEqual(self.backend_hits, 0)
        finally:
            connection.close()

    def test_declared_body_charset_is_inspected_and_invalid_charsets_fail_closed(self) -> None:
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            self.proxy.port,
            timeout=3,
        )
        try:
            encoded_attack = "<script>alert(1)</script>".encode("utf-16")
            connection.request(
                "POST",
                "/submit",
                body=encoded_attack,
                headers={"Content-Type": "application/x-www-form-urlencoded; charset=utf-16"},
            )
            blocked = connection.getresponse()
            self.assertEqual(blocked.status, 403)
            blocked.read()

            connection.request(
                "POST",
                "/submit",
                body=encoded_attack,
            )
            bom_blocked = connection.getresponse()
            self.assertEqual(bom_blocked.status, 403)
            bom_blocked.read()

            connection.request(
                "POST",
                "/submit",
                body=b"query=normal",
                headers={"Content-Type": "application/x-www-form-urlencoded; charset=x-unknown"},
            )
            unsupported = connection.getresponse()
            self.assertEqual(unsupported.status, 415)
            unsupported.read()

            connection.request(
                "POST",
                "/submit",
                body=b"\xff",
                headers={"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
            )
            malformed = connection.getresponse()
            self.assertEqual(malformed.status, 400)
            malformed.read()
            self.assertEqual(self.backend_hits, 0)
        finally:
            connection.close()

    def test_rule_changes_apply_without_restarting_proxy(self) -> None:
        connection = http.client.HTTPConnection("127.0.0.1", self.proxy.port, timeout=3)
        try:
            self.proxy.configure_rules(
                {rule.id for rule in RULES},
                {rule.id: rule.weight for rule in RULES},
                6,
            )
            suspicious_path = "/search?q=" + quote("<script>alert(1)</script>")
            connection.request("GET", suspicious_path)
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            response.read()
            self.assertEqual(self.backend_hits, 1)

            updated_weights = {rule.id: rule.weight for rule in RULES}
            updated_weights["XSS-01"] = 6
            self.proxy.configure_rules(
                {rule.id for rule in RULES},
                updated_weights,
                6,
            )
            connection.request("GET", suspicious_path)
            blocked = connection.getresponse()
            self.assertEqual(blocked.status, 403)
            blocked.read()
            self.assertEqual(self.backend_hits, 1)

            self.proxy.configure_rules(
                {rule.id for rule in RULES if rule.id != "XSS-01"},
                updated_weights,
                6,
            )
            connection.request("GET", suspicious_path)
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            response.read()
            self.assertEqual(self.backend_hits, 2)
        finally:
            connection.close()

    def test_access_lists_apply_without_restarting_proxy(self) -> None:
        connection = http.client.HTTPConnection("127.0.0.1", self.proxy.port, timeout=3)
        try:
            self.proxy.configure_access_lists(
                ("127.0.0.1",),
                ("127.0.0.1",),
                (),
            )
            connection.request("GET", "/products")
            blocked = connection.getresponse()
            self.assertEqual(blocked.status, 403)
            blocked.read()
            self.assertEqual(self.backend_hits, 0)

            self.proxy.configure_access_lists(
                ("127.0.0.1",),
                (),
                (),
            )
            suspicious_path = "/search?q=" + quote("<script>alert(1)</script>")
            connection.request("GET", suspicious_path)
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            response.read()
            self.assertEqual(self.backend_hits, 1)

            self.proxy.configure_access_lists(
                (),
                (),
                (re.compile(r"^/safe$"),),
            )
            path_bypass = "/safe?q=" + quote("<script>alert(1)</script>")
            connection.request("GET", path_bypass)
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            response.read()
            self.assertEqual(self.backend_hits, 2)
        finally:
            connection.close()

    def test_invalid_management_settings_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.proxy.configure_rules(set(), {}, 3)
        with self.assertRaises(ValueError):
            self.proxy.configure_access_lists(("not-an-ip",), (), ())

    def test_invalid_combined_policy_update_rolls_back_all_policy_changes(self) -> None:
        weights = {rule.id: rule.weight for rule in RULES}
        with self.assertRaises(ValueError):
            self.proxy.configure_policy(
                {rule.id for rule in RULES},
                weights,
                3,
                ("127.0.0.1",),
                (),
                (),
                0,
                10,
            )

        connection = http.client.HTTPConnection(
            "127.0.0.1",
            self.proxy.port,
            timeout=3,
        )
        try:
            connection.request(
                "GET",
                "/search?q=" + quote("<script>alert(1)</script>"),
            )
            response = connection.getresponse()
            self.assertEqual(response.status, 403)
            response.read()
            self.assertEqual(self.backend_hits, 0)
        finally:
            connection.close()

    def test_health_endpoint_is_minimal_and_obeys_host_and_ip_controls(self) -> None:
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            self.proxy.port,
            timeout=3,
        )
        try:
            connection.request("GET", "/__waf/health")
            health = connection.getresponse()
            payload = health.read()
            self.assertEqual(health.status, 200)
            self.assertEqual(payload, b'{\n  "status": "ok"\n}')
            self.assertNotIn(b"top_clients", payload)
            self.assertEqual(health.getheader("Cache-Control"), "no-store")
        finally:
            connection.close()

        self.proxy.configure_access_lists((), ("127.0.0.1",), ())
        blocked_connection = http.client.HTTPConnection(
            "127.0.0.1",
            self.proxy.port,
            timeout=3,
        )
        try:
            blocked_connection.request("GET", "/__waf/health")
            blocked = blocked_connection.getresponse()
            self.assertEqual(blocked.status, 403)
            blocked.read()
        finally:
            blocked_connection.close()

        invalid_host_connection = http.client.HTTPConnection(
            "127.0.0.1",
            self.proxy.port,
            timeout=3,
        )
        try:
            invalid_host_connection.request(
                "GET",
                "/__waf/health",
                headers={"Host": "attacker.invalid"},
            )
            invalid_host = invalid_host_connection.getresponse()
            self.assertEqual(invalid_host.status, 421)
            invalid_host.read()
        finally:
            invalid_host_connection.close()

    def test_duplicate_host_and_content_length_headers_are_rejected(self) -> None:
        for headers in (
            b"Host: 127.0.0.1\r\nHost: attacker.invalid\r\n",
            b"Host: 127.0.0.1\r\nContent-Length: 0\r\nContent-Length: 1\r\n",
        ):
            request = (
                b"GET /safe HTTP/1.1\r\n"
                + headers
                + b"Connection: close\r\n\r\n"
            )
            with socket.create_connection(("127.0.0.1", self.proxy.port), timeout=3) as client:
                client.sendall(request)
                response = client.recv(4096)
            self.assertIn(b" 400 ", response.split(b"\r\n", 1)[0])


if __name__ == "__main__":
    unittest.main()
