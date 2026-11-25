from __future__ import annotations

import json
import queue
import tkinter as tk
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from applications import ApplicationRegistry
from app import WAFDesktopApp
from waf import BLOCK_THRESHOLD, RULES, FirewallEvent


class EventPauseTests(unittest.TestCase):
    def test_paused_events_are_ingested_after_resume(self) -> None:
        app = WAFDesktopApp.__new__(WAFDesktopApp)
        app.root = tk.Tcl()
        app.events = queue.Queue[FirewallEvent]()
        app._pending_events = []
        app._paused = True
        app._recent_timestamps = []
        app._ingest_event = Mock()

        paused_event = FirewallEvent("", "ALLOWED", "GET", "/paused", "127.0.0.1", 200, "")
        resumed_event = FirewallEvent("", "ALLOWED", "GET", "/resumed", "127.0.0.1", 200, "")
        app.events.put(paused_event)

        app._drain_events()

        self.assertEqual(app.events.qsize(), 0)
        self.assertEqual(app._pending_events, [paused_event])
        app._ingest_event.assert_not_called()

        app._paused = False
        app.events.put(resumed_event)
        app._drain_events()

        self.assertEqual(
            [call.args[0] for call in app._ingest_event.call_args_list],
            [paused_event, resumed_event],
        )
        self.assertEqual(app._pending_events, [])

    def test_application_event_is_enqueued_for_the_ui_thread(self) -> None:
        app = WAFDesktopApp.__new__(WAFDesktopApp)
        app.application_events = queue.Queue()
        event = FirewallEvent(
            "",
            "BLOCKED",
            "GET",
            "/attack",
            "127.0.0.1",
            403,
            "Script tag",
        )

        app._queue_application_event("app-1", event)

        app_id, queued_event = app.application_events.get_nowait()
        self.assertEqual(app_id, "app-1")
        self.assertIs(queued_event, event)


class StatusPillTests(unittest.TestCase):
    def test_badge_only_reports_local_active_after_inspected_traffic(self) -> None:
        self.assertEqual(
            WAFDesktopApp._status_pill_state(False, False, False),
            ("STOPPED", "warn"),
        )
        self.assertEqual(
            WAFDesktopApp._status_pill_state(True, False, False),
            ("LOCAL WAITING", "warn"),
        )
        self.assertEqual(
            WAFDesktopApp._status_pill_state(True, False, True),
            ("LOCAL ACTIVE", "good"),
        )
        self.assertEqual(
            WAFDesktopApp._status_pill_state(True, True, True),
            ("LOG PAUSED", "accent"),
        )


class TrafficSeriesTests(unittest.TestCase):
    def test_series_is_zero_filled_and_limited_to_the_last_60_seconds(self) -> None:
        app = WAFDesktopApp.__new__(WAFDesktopApp)
        app._traffic_buckets = {
            40: [9, 0],
            41: [1, 2],
            100: [0, 4],
            101: [6, 0],
        }

        series = app._traffic_series(100)

        self.assertEqual(len(series), 60)
        self.assertEqual(series[0], (41, 1, 2))
        self.assertEqual(series[-1], (100, 0, 4))
        self.assertEqual(series[30], (71, 0, 0))


class ConfigurationPersistenceTests(unittest.TestCase):
    def _new_app(self, config_path: Path) -> WAFDesktopApp:
        app = WAFDesktopApp.__new__(WAFDesktopApp)
        app._config_path = config_path
        app._enabled_rule_ids = {rule.id for rule in RULES}
        app._rule_weights = {rule.id: rule.weight for rule in RULES}
        app._block_threshold = BLOCK_THRESHOLD
        app._allowlist_ips = []
        app._blocklist_ips = []
        app._path_bypasses = []
        return app

    def test_saves_and_reloads_waf_settings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "settings" / "config.json"
            saved = self._new_app(config_path)
            saved._enabled_rule_ids.remove("XSS-01")
            saved._rule_weights["SQLI-01"] = 8
            saved._block_threshold = 7
            saved._allowlist_ips = ["192.0.2.0/24"]
            saved._blocklist_ips = ["2001:db8::1/128"]
            saved._path_bypasses = ["/health"]

            saved._save_configuration()
            restored = self._new_app(config_path)
            restored._load_configuration()

            self.assertEqual(restored._enabled_rule_ids, saved._enabled_rule_ids)
            self.assertEqual(restored._rule_weights, saved._rule_weights)
            self.assertEqual(restored._block_threshold, 7)
            self.assertEqual(restored._allowlist_ips, ["192.0.2.0/24"])
            self.assertEqual(restored._blocklist_ips, ["2001:db8::1/128"])
            self.assertEqual(restored._path_bypasses, ["/health"])

    def test_invalid_saved_settings_do_not_partially_load(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.json"
            invalid = self._new_app(config_path)._configuration_data()
            invalid["path_bypasses"] = ["//invalid"]
            config_path.write_text(json.dumps(invalid), encoding="utf-8")
            app = self._new_app(config_path)

            with self.assertRaises(ValueError):
                app._load_configuration()

            self.assertEqual(app._enabled_rule_ids, {rule.id for rule in RULES})
            self.assertEqual(app._rule_weights, {rule.id: rule.weight for rule in RULES})
            self.assertEqual(app._block_threshold, BLOCK_THRESHOLD)
            self.assertEqual(app._allowlist_ips, [])
            self.assertEqual(app._path_bypasses, [])

    def test_application_registry_is_saved_and_reloaded_with_waf_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "config.json"
            saved = self._new_app(config_path)
            saved._saved_applications = []
            saved.application_registry = ApplicationRegistry(
                log_directory=root / "events",
                audit_path=root / "audit.jsonl",
            )
            spec = saved.application_registry.add_application(
                {
                    "name": "Local test app",
                    "backend_url": "http://127.0.0.1:8000",
                    "hostnames": ["shop.example.test"],
                    "listen_port": 8081,
                    "authorized": True,
                },
                confirmed=True,
            )
            saved._save_configuration()

            restored = self._new_app(config_path)
            restored._load_configuration()

            self.assertEqual(len(restored._saved_applications), 1)
            self.assertEqual(restored._saved_applications[0]["id"], spec.id)
            self.assertEqual(
                restored._saved_applications[0]["hostnames"],
                ["shop.example.test"],
            )

    def test_configuration_save_failure_keeps_previous_file_intact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.json"
            original = '{"version": 1, "preserve": true}\n'
            config_path.write_text(original, encoding="utf-8")
            app = self._new_app(config_path)
            app._saved_applications = []

            with patch("app.os.replace", side_effect=OSError("disk unavailable")):
                with self.assertRaisesRegex(OSError, "disk unavailable"):
                    app._save_configuration()

            self.assertEqual(config_path.read_text(encoding="utf-8"), original)
            self.assertEqual(list(Path(directory).glob(".config.json.*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
