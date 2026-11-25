"""Self-contained Tkinter UI for the RIZVI WAF desktop app."""

from __future__ import annotations

import csv
import ipaddress
import json
import os
import queue
import re
import tempfile
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import TypeVar
from urllib.parse import urlparse

from applications import ApplicationRegistry, ApplicationView
from waf import BLOCK_THRESHOLD, RULES, FirewallEvent, WAFProxy


# --------------------------------------------------------------------------- #
# Theme definitions
# --------------------------------------------------------------------------- #
THEMES = {
    "midnight": {
        "bg":           "#101820",
        "panel":        "#17232d",
        "panel_alt":    "#1e2c38",
        "header":       "#233440",
        "fg":           "#e7edf2",
        "fg_dim":       "#9fb1bb",
        "fg_muted":     "#718590",
        "accent":       "#61b8c5",
        "accent_hover": "#7fd0dc",
        "good":         "#52c49a",
        "bad":          "#f07878",
        "warn":         "#e1a95b",
        "selected":     "#235a68",
        "entry_bg":     "#0d151b",
        "entry_fg":     "#e7edf2",
    },
    "daylight": {
        "bg":           "#f4f6f8",
        "panel":        "#ffffff",
        "panel_alt":    "#eef2f5",
        "header":       "#dbe3e9",
        "fg":           "#1c2731",
        "fg_dim":       "#4a5b68",
        "fg_muted":     "#7d8f9c",
        "accent":       "#0f7c8f",
        "accent_hover": "#0a5d6b",
        "good":         "#1c8f68",
        "bad":          "#c33e3e",
        "warn":         "#b5791a",
        "selected":     "#b8dee6",
        "entry_bg":     "#ffffff",
        "entry_fg":     "#1c2731",
    },
}

_TWidget = TypeVar("_TWidget", bound=tk.Widget)


class WAFDesktopApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("RIZVI WAF")
        self.root.geometry("1120x760")
        self.root.minsize(900, 600)

        self.events: queue.Queue[FirewallEvent] = queue.Queue()
        self.application_events: queue.Queue[tuple[str, FirewallEvent]] = queue.Queue()
        self._pending_events: list[FirewallEvent] = []
        self.proxy: WAFProxy | None = None
        self._enabled_rule_ids = {rule.id for rule in RULES}
        self._rule_weights = {rule.id: rule.weight for rule in RULES}
        self._block_threshold = BLOCK_THRESHOLD
        self._allowlist_ips: list[str] = []
        self._blocklist_ips: list[str] = []
        self._path_bypasses: list[str] = []
        self._config_path = self._default_config_path()
        self._config_load_error: str | None = None
        self._saved_applications: list[dict[str, object]] = []
        try:
            self._load_configuration()
        except (OSError, ValueError) as exc:
            self._config_load_error = str(exc)
        try:
            self.application_registry = ApplicationRegistry(
                applications=self._saved_applications,
                log_directory=self._config_path.parent / "application-events",
                audit_path=self._config_path.parent / "audit.jsonl",
                event_callback=self._queue_application_event,
                change_callback=self._save_application_configuration,
            )
        except (OSError, ValueError) as exc:
            self._config_load_error = (
                f"Application registry could not be loaded: {exc}"
            )
            self.application_registry = ApplicationRegistry(
                log_directory=self._config_path.parent / "application-events",
                audit_path=self._config_path.parent / "audit.jsonl",
                event_callback=self._queue_application_event,
                change_callback=self._save_application_configuration,
            )
        self.allowed_count = 0
        self.blocked_count = 0

        self._theme_name = "midnight"
        self._paused = False
        self._autoscroll = tk.BooleanVar(value=True)
        self._filter_var = tk.StringVar()
        self._filter_var.trace_add("write", lambda *_: self._apply_filter())
        self._apps_filter_var = tk.StringVar()
        self._apps_filter_var.trace_add("write", lambda *_: self._refresh_applications_table())
        self._applications_refresh_id: str | None = None

        self._recent_timestamps: list[float] = []
        self._traffic_buckets: dict[int, list[int]] = {}
        self._row_ids: list[str] = []
        self._started_at: float | None = None
        self._active_page = "Traffic"
        self._stat_labels: dict[str, list[tk.Label]] = {}
        self._widgets_theme: list[tuple[tk.Widget, str]] = []  # (widget, role)

        self._configure_styles()
        self._build_layout()
        self._apply_theme()
        if self._config_load_error is not None:
            messagebox.showerror(
                "Saved WAF settings could not be loaded",
                "Defaults are active for this session. The saved file was left unchanged:\n"
                f"{self._config_path}\n\n{self._config_load_error}",
                parent=self.root,
            )

        self.root.after(100, self._drain_events)
        self.root.after(1000, self._update_throughput)
        self.root.protocol("WM_DELETE_WINDOW", self._close)
        self._bind_shortcuts()

    @staticmethod
    def _default_config_path() -> Path:
        app_data = os.environ.get("APPDATA")
        if app_data:
            return Path(app_data) / "RIZVI WAF" / "config.json"
        return Path.home() / ".config" / "rizvi-waf" / "config.json"

    @staticmethod
    def _normalise_saved_ips(field: str, values: object) -> list[str]:
        if not isinstance(values, list) or any(type(value) is not str for value in values):
            raise ValueError(f"{field} must be a list of IP or CIDR strings.")
        normalized: list[str] = []
        for value in values:
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid {field} entry: {value!r}") from exc
            canonical = str(network)
            if canonical not in normalized:
                normalized.append(canonical)
        return normalized

    @staticmethod
    def _normalise_path_bypass(value: str) -> str:
        if (
            not value.startswith("/")
            or value.startswith("//")
            or "?" in value
            or "#" in value
            or len(value) > 240
        ):
            raise ValueError("Enter one exact path, such as /health.")
        return value

    def _load_configuration(self) -> None:
        try:
            document = json.loads(self._config_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        if not isinstance(document, dict):
            raise ValueError("The saved configuration must be a JSON object.")
        if type(document.get("version")) is not int or document["version"] != 1:
            raise ValueError("The saved configuration has an unsupported version.")

        known_rule_ids = {rule.id for rule in RULES}
        enabled_values = document.get("enabled_rule_ids")
        if (
            not isinstance(enabled_values, list)
            or any(type(rule_id) is not str for rule_id in enabled_values)
        ):
            raise ValueError("enabled_rule_ids must be a list of rule IDs.")
        enabled_ids = set(enabled_values)
        if (
            not enabled_ids
            or len(enabled_ids) != len(enabled_values)
            or not enabled_ids <= known_rule_ids
        ):
            raise ValueError("The saved enabled rule IDs are empty, duplicated, or unknown.")

        weights = document.get("rule_weights")
        if not isinstance(weights, dict) or set(weights) != known_rule_ids:
            raise ValueError("rule_weights must contain one weight for every known rule.")
        if any(type(weight) is not int or not 1 <= weight <= 100 for weight in weights.values()):
            raise ValueError("Saved rule weights must be integers from 1 to 100.")
        threshold = document.get("block_threshold")
        if type(threshold) is not int or not 1 <= threshold <= 100:
            raise ValueError("The saved block threshold must be from 1 to 100.")

        allowlist_ips = self._normalise_saved_ips(
            "allowlist_ips", document.get("allowlist_ips")
        )
        blocklist_ips = self._normalise_saved_ips(
            "blocklist_ips", document.get("blocklist_ips")
        )
        path_values = document.get("path_bypasses")
        if not isinstance(path_values, list) or any(type(path) is not str for path in path_values):
            raise ValueError("path_bypasses must be a list of exact path strings.")
        path_bypasses = list(
            dict.fromkeys(self._normalise_path_bypass(path) for path in path_values)
        )
        applications_value = document.get("applications", [])
        if not isinstance(applications_value, list):
            raise ValueError("applications must be a list.")
        application_specs = ApplicationRegistry.validate_catalog(applications_value)

        self._enabled_rule_ids = enabled_ids
        self._rule_weights = dict(weights)
        self._block_threshold = threshold
        self._allowlist_ips = allowlist_ips
        self._blocklist_ips = blocklist_ips
        self._path_bypasses = path_bypasses
        self._saved_applications = [spec.to_dict() for spec in application_specs]

    def _configuration_data(self) -> dict[str, object]:
        return {
            "version": 1,
            "enabled_rule_ids": sorted(self._enabled_rule_ids),
            "rule_weights": self._rule_weights,
            "block_threshold": self._block_threshold,
            "allowlist_ips": self._allowlist_ips,
            "blocklist_ips": self._blocklist_ips,
            "path_bypasses": self._path_bypasses,
            "applications": (
                self.application_registry.configurations()
                if hasattr(self, "application_registry")
                else getattr(self, "_saved_applications", [])
            ),
        }

    def _save_application_configuration(self) -> None:
        self._save_configuration_with_feedback("Application registry updated")

    def _save_configuration(self) -> None:
        temporary_path: Path | None = None
        try:
            self._config_path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                newline="\n",
                dir=self._config_path.parent,
                prefix=f".{self._config_path.name}.",
                suffix=".tmp",
                delete=False,
            ) as config_file:
                temporary_path = Path(config_file.name)
                json.dump(self._configuration_data(), config_file, indent=2, sort_keys=True)
                config_file.write("\n")
                config_file.flush()
                os.fsync(config_file.fileno())
            os.replace(temporary_path, self._config_path)
        except OSError:
            if temporary_path is not None:
                try:
                    temporary_path.unlink()
                except FileNotFoundError:
                    pass
                except OSError:
                    pass
            raise

    def _save_configuration_with_feedback(self, detail: str) -> None:
        try:
            self._save_configuration()
        except OSError as exc:
            self.bottom_status.configure(text=f"{detail} — save failed")
            messagebox.showerror(
                "WAF settings applied but not saved",
                f"{detail}, but the configuration file could not be written:\n"
                f"{self._config_path}\n\n{exc}",
                parent=self.root,
            )
        else:
            self.bottom_status.configure(text=f"{detail} and saved")

    # ------------------------------------------------------------------ #
    # Style / theme
    # ------------------------------------------------------------------ #
    def _configure_styles(self) -> None:
        self.style = ttk.Style()
        self.style.theme_use("clam")

    def _apply_theme(self) -> None:
        t = THEMES[self._theme_name]
        self.root.configure(bg=t["bg"])

        self.style.configure(
            "Treeview",
            background=t["panel"],
            fieldbackground=t["panel"],
            foreground=t["fg"],
            rowheight=30,
            borderwidth=0,
            font=("Segoe UI", 9),
        )
        self.style.configure(
            "Treeview.Heading",
            background=t["header"],
            foreground=t["fg"],
            font=("Segoe UI", 9, "bold"),
            relief="flat",
        )
        self.style.map(
            "Treeview",
            background=[("selected", t["selected"])],
            foreground=[("selected", t["fg"])],
        )
        self.style.configure(
            "TEntry",
            fieldbackground=t["entry_bg"],
            foreground=t["entry_fg"],
            insertcolor=t["entry_fg"],
            bordercolor=t["header"],
            lightcolor=t["header"],
            darkcolor=t["header"],
        )
        self.style.configure(
            "TButton",
            background=t["panel_alt"],
            foreground=t["fg"],
            bordercolor=t["header"],
            focuscolor=t["accent"],
            font=("Segoe UI", 9, "bold"),
            padding=(12, 6),
        )
        self.style.map(
            "TButton",
            background=[("active", t["accent"]), ("disabled", t["panel"])],
            foreground=[("disabled", t["fg_muted"])],
        )
        self.style.configure(
            "Accent.TButton",
            background=t["accent"],
            foreground="#ffffff" if self._theme_name == "midnight" else "#ffffff",
        )
        self.style.map(
            "Accent.TButton",
            background=[("active", t["accent_hover"]), ("disabled", t["panel"])],
        )
        self.style.configure(
            "TCheckbutton",
            background=t["panel"],
            foreground=t["fg"],
            font=("Segoe UI", 9),
        )
        self.style.map(
            "TCheckbutton",
            background=[("active", t["panel"])],
            foreground=[("active", t["fg"])],
        )
        self.style.configure("TNotebook", background=t["bg"], borderwidth=0)
        self.style.configure(
            "TNotebook.Tab",
            background=t["panel_alt"],
            foreground=t["fg_dim"],
            padding=(12, 7),
        )
        self.style.map(
            "TNotebook.Tab",
            background=[("selected", t["selected"])],
            foreground=[("selected", t["fg"])],
        )

        # Repaint non-ttk widgets
        for widget, role in self._widgets_theme:
            if role.endswith("_fg"):
                continue
            try:
                widget.configure(**{"bg": t[role]})
            except tk.TclError:
                pass
        self._recolor_labels()
        self._configure_application_status_tags()

        self.table.tag_configure("blocked", foreground=t["bad"])
        self.table.tag_configure("allowed", foreground=t["good"])
        self._update_nav_buttons()

    def _register(self, widget: _TWidget, role: str) -> _TWidget:
        self._widgets_theme.append((widget, role))
        return widget

    def _recolor_labels(self) -> None:
        """Re-apply fg colors that were set by role."""
        for widget, role in self._widgets_theme:
            if role.endswith("_fg"):
                try:
                    widget.configure(
                        **{"fg": THEMES[self._theme_name][role[:-3]]}
                    )
                except tk.TclError:
                    pass

    def _set_foreground(self, widget: tk.Widget, role: str) -> None:
        self._widgets_theme.append((widget, f"{role}_fg"))
        widget.configure(**{"fg": THEMES[self._theme_name][role]})

    def _toggle_theme(self) -> None:
        self._theme_name = "daylight" if self._theme_name == "midnight" else "midnight"
        self._apply_theme()
        self.theme_button.configure(
            text="☾  Dark theme" if self._theme_name == "daylight" else "☀  Light theme"
        )
        self._update_status_pill()

    # ------------------------------------------------------------------ #
    # Layout
    # ------------------------------------------------------------------ #
    def _build_layout(self) -> None:
        # ---------- Header ----------
        header = tk.Frame(self.root, padx=24, pady=15)
        self._register(header, "bg")
        header.pack(fill="x")

        self._register(tk.Label(
            header, text="RIZVI WAF",
            font=("Segoe UI", 23, "bold"),
        ), "bg").pack(side="left")
        self._title_label = self._widgets_theme[-1][0]
        self._set_foreground(self._title_label, "fg")

        self._register(tk.Label(
            header, text="REAL-TIME WEB APPLICATION FIREWALL",
            font=("Segoe UI", 9, "bold"),
        ), "bg").pack(side="left", padx=(16, 0), pady=(9, 0))
        self._subtitle_label = self._widgets_theme[-1][0]
        self._set_foreground(self._subtitle_label, "fg_muted")

        right = tk.Frame(header)
        self._register(right, "bg")
        right.pack(side="right")

        self.search_entry = ttk.Entry(
            right, textvariable=self._filter_var, width=25
        )
        self.search_entry.pack(side="left", padx=(0, 12))

        self.theme_button = ttk.Button(right, text="☀  Light theme", command=self._toggle_theme)
        self.theme_button.pack(side="left", padx=(0, 10))

        self.status_pill = tk.Frame(right, padx=12, pady=6)
        self._register(self.status_pill, "panel_alt")
        self.status_pill.pack(side="left")

        self.status_dot = self._register(
            tk.Label(self.status_pill, text="●", font=("Segoe UI", 12, "bold")),
            "panel_alt",
        )
        self._set_foreground(self.status_dot, "warn")
        self.status_dot.pack(side="left")

        self.status_label = self._register(
            tk.Label(self.status_pill, text="STOPPED", font=("Segoe UI", 9, "bold")),
            "panel_alt",
        )
        self._set_foreground(self.status_label, "fg")
        self.status_label.pack(side="left", padx=(6, 0))

        # ---------- Sidebar and page container ----------
        body = tk.Frame(self.root)
        self._register(body, "bg")
        body.pack(fill="both", expand=True)

        sidebar = tk.Frame(body, width=170, padx=10, pady=18)
        self._register(sidebar, "panel")
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        nav_title = self._register(
            tk.Label(sidebar, text="WORKSPACE", font=("Segoe UI", 8, "bold")),
            "panel",
        )
        self._set_foreground(nav_title, "fg_muted")
        nav_title.pack(anchor="w", padx=10, pady=(4, 13))

        self._nav_buttons: dict[str, tk.Button] = {}
        page_names = (
            "Traffic",
            "Connected Applications",
            "Manage",
            "Stats",
            "Settings",
            "About",
        )
        navigation_labels = {"Connected Applications": "Connected Apps"}
        for name in page_names:
            button = tk.Button(
                sidebar,
                text=f"  {navigation_labels.get(name, name)}",
                anchor="w",
                relief="flat",
                borderwidth=0,
                padx=10,
                pady=10,
                font=("Segoe UI", 10, "bold"),
                command=lambda page=name: self._show_page(page),
            )
            self._register(button, "panel")
            button.pack(fill="x", pady=2)
            self._nav_buttons[name] = button

        self.page_container = tk.Frame(body, padx=18, pady=16)
        self._register(self.page_container, "bg")
        self.page_container.pack(side="left", fill="both", expand=True)
        self.pages: dict[str, tk.Frame] = {}
        for name in page_names:
            page = tk.Frame(self.page_container)
            self._register(page, "bg")
            self.pages[name] = page

        self._build_traffic_page(self.pages["Traffic"])
        self._build_applications_page(self.pages["Connected Applications"])
        self._build_management_page(self.pages["Manage"])
        self._build_stats_page(self.pages["Stats"])
        self._build_settings_page(self.pages["Settings"])
        self._build_about_page(self.pages["About"])
        self._show_page("Traffic")

        # ---------- Footer ----------
        bar = tk.Frame(self.root, padx=28, pady=6)
        self._register(bar, "bg")
        bar.pack(fill="x")

        self.bottom_status = self._register(
            tk.Label(
                bar,
                text="Ready · Local heuristic WAF; not production protection.",
                font=("Segoe UI", 8), anchor="w",
            ),
            "bg",
        )
        self._set_foreground(self.bottom_status, "fg_muted")
        self.bottom_status.pack(side="left", fill="x", expand=True)

        self.throughput_label = self._register(
            tk.Label(bar, text="0 ev/s", font=("Segoe UI", 8, "bold")),
            "bg",
        )
        self._set_foreground(self.throughput_label, "accent")
        self.throughput_label.pack(side="left", padx=(12, 0))
        self.uptime_label = self._register(
            tk.Label(bar, text="Uptime 00:00:00", font=("Segoe UI", 8)),
            "bg",
        )
        self._set_foreground(self.uptime_label, "fg_muted")
        self.uptime_label.pack(side="left", padx=(14, 0))

        self._register(tk.Label(
            bar, text="F5 Start · F6 Stop · Ctrl+L Clear · Ctrl+F Search · Ctrl+T Theme",
            font=("Segoe UI", 8),
        ), "bg").pack(side="right")
        self._set_foreground(self._widgets_theme[-1][0], "fg_muted")
        self._applications_refresh_id = self.root.after(
            250,
            self._scheduled_applications_refresh,
        )

        # ---------- Context menu ----------
        self._context_menu = tk.Menu(self.root, tearoff=0)
        self._context_menu.add_command(label="Copy path",   command=lambda: self._copy_cell("path"))
        self._context_menu.add_command(label="Copy client", command=lambda: self._copy_cell("client"))
        self._context_menu.add_command(label="Copy row",    command=self._copy_row)
        self._context_menu.add_separator()
        self._context_menu.add_command(label="Show details", command=self._show_detail)

    def _build_traffic_page(self, page: tk.Frame) -> None:
        settings = tk.Frame(page, padx=18, pady=14)
        self._register(settings, "panel")
        settings.pack(fill="x", pady=(0, 12))
        settings.columnconfigure(0, weight=1)

        self._register(
            tk.Label(settings, text="BACKEND URL", font=("Segoe UI", 8, "bold")),
            "panel",
        ).grid(row=0, column=0, sticky="w")
        self._set_foreground(self._widgets_theme[-1][0], "fg_dim")
        self._register(
            tk.Label(settings, text="LISTEN PORT", font=("Segoe UI", 8, "bold")),
            "panel",
        ).grid(row=0, column=1, sticky="w", padx=(14, 0))
        self._set_foreground(self._widgets_theme[-1][0], "fg_dim")

        self.backend_entry = ttk.Entry(settings)
        self.backend_entry.insert(0, "http://127.0.0.1:8000")
        self.backend_entry.grid(row=1, column=0, sticky="ew", pady=(7, 0))
        self.port_entry = ttk.Entry(settings, width=11)
        self.port_entry.insert(0, "8080")
        self.port_entry.grid(row=1, column=1, sticky="w", padx=(14, 0), pady=(7, 0))
        self.start_button = ttk.Button(
            settings, text="▶  Start firewall", style="Accent.TButton", command=self._start
        )
        self.start_button.grid(row=1, column=2, padx=(18, 8), pady=(7, 0))
        self.stop_button = ttk.Button(
            settings, text="■  Stop", command=self._stop, state="disabled"
        )
        self.stop_button.grid(row=1, column=3, pady=(7, 0))
        self.status_detail = self._register(
            tk.Label(
                settings,
                text="Proxy listens on 127.0.0.1 only",
                font=("Segoe UI", 8),
                anchor="w",
            ),
            "panel",
        )
        self._set_foreground(self.status_detail, "fg_muted")
        self.status_detail.grid(row=2, column=0, columnspan=4, sticky="w", pady=(10, 0))

        stats = tk.Frame(page)
        self._register(stats, "bg")
        stats.pack(fill="x", pady=(0, 12))
        self.allowed_label = self._stat_card(stats, "ALLOWED", "0", "good", "allowed")
        self.blocked_label = self._stat_card(stats, "BLOCKED", "0", "bad", "blocked")
        self.total_label = self._stat_card(stats, "TOTAL INSPECTED", "0", "accent", "total")
        self.rate_label = self._stat_card(stats, "BLOCK RATE", "0%", "warn", "rate")

        toolbar = tk.Frame(page)
        self._register(toolbar, "bg")
        toolbar.pack(fill="x", pady=(0, 7))
        ttk.Checkbutton(
            toolbar,
            text="Auto-scroll newest first",
            variable=self._autoscroll,
            command=self._on_autoscroll_toggle,
        ).pack(side="left")
        self.pause_button = ttk.Button(toolbar, text="⏸  Pause", command=self._toggle_pause)
        self.pause_button.pack(side="right")
        ttk.Button(toolbar, text="⬇  Export CSV", command=self._export_csv).pack(
            side="right", padx=(0, 8)
        )
        ttk.Button(toolbar, text="🗑  Clear", command=self._clear_log).pack(
            side="right", padx=(0, 8)
        )

        events_frame = tk.Frame(page, padx=14, pady=12)
        self._register(events_frame, "panel")
        events_frame.pack(fill="both", expand=True)
        table_title = self._register(
            tk.Label(events_frame, text="LIVE TRAFFIC", font=("Segoe UI", 10, "bold")),
            "panel",
        )
        self._set_foreground(table_title, "fg")
        table_title.pack(anchor="w", padx=5, pady=(0, 10))
        columns = ("time", "action", "method", "path", "client", "status", "rule")
        self.table = ttk.Treeview(
            events_frame, columns=columns, show="headings", selectmode="browse"
        )
        headings = {
            "time": ("TIME", 82),
            "action": ("ACTION", 88),
            "method": ("METHOD", 72),
            "path": ("PATH", 220),
            "client": ("CLIENT", 110),
            "status": ("STATUS", 68),
            "rule": ("RULE / RESULT", 210),
        }
        for column, (label, width) in headings.items():
            self.table.heading(
                column, text=label, command=lambda c=column: self._sort_column(c)
            )
            self.table.column(
                column,
                width=width,
                minwidth=55,
                stretch=column in {"path", "rule"},
            )
        scrollbar = ttk.Scrollbar(events_frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.table.pack(fill="both", expand=True)
        self.table.bind("<Double-1>", self._show_detail)
        self.table.bind("<Button-3>", self._show_context_menu)

    def _build_applications_page(self, page: tk.Frame) -> None:
        self._page_heading(
            page,
            "Connected applications",
            "Register authorized backends and give each one an isolated WAF listener and policy.",
        )
        notice = self._register(
            tk.Label(
                page,
                text=(
                    "Registration does not activate protection. A listener is reported as "
                    "protected only after it has inspected real traffic. Listeners bind to "
                    "127.0.0.1; use a trusted TLS-terminating reverse proxy for public access."
                ),
                font=("Segoe UI", 9),
                anchor="w",
                justify="left",
                wraplength=800,
            ),
            "bg",
        )
        self._set_foreground(notice, "warn")
        notice.pack(fill="x", pady=(0, 12))

        actions = tk.Frame(page)
        self._register(actions, "bg")
        actions.pack(fill="x", pady=(0, 8))
        first_row = (
            ("Add Application", self._add_application),
            ("Connect", self._connect_application),
            ("Start Protection", self._start_application_protection),
            ("Stop Protection", self._stop_application_protection),
            ("Edit", self._edit_application),
        )
        second_row = (
            ("Monitor", self._monitor_application),
            ("Manage Rules", self._manage_application_rules),
            ("View Attacks", self._view_application_attacks),
            ("Generate Report", self._generate_application_report),
            ("Disconnect", self._disconnect_application),
        )
        for buttons in (first_row, second_row):
            row = tk.Frame(actions)
            self._register(row, "bg")
            row.pack(fill="x", pady=(0, 5))
            for label, command in buttons:
                ttk.Button(row, text=label, command=command).pack(
                    side="left",
                    padx=(0, 7),
                )

        registry_toolbar = tk.Frame(page)
        self._register(registry_toolbar, "bg")
        registry_toolbar.pack(fill="x", pady=(0, 8))
        ttk.Label(registry_toolbar, text="Filter applications").pack(side="left")
        app_filter = ttk.Entry(
            registry_toolbar,
            textvariable=self._apps_filter_var,
            width=28,
        )
        app_filter.pack(side="left", padx=(8, 10))
        ttk.Button(
            registry_toolbar,
            text="Refresh",
            command=self._refresh_applications_table,
        ).pack(side="left")

        frame = tk.Frame(page, padx=12, pady=10)
        self._register(frame, "panel")
        frame.pack(fill="both", expand=True)
        self.apps_table = ttk.Treeview(
            frame,
            columns=(
                "name",
                "backend",
                "port",
                "connection",
                "protection",
                "inspected",
                "blocked",
            ),
            show="headings",
            selectmode="browse",
        )
        for column, heading, width in (
            ("name", "APPLICATION", 140),
            ("backend", "BACKEND", 230),
            ("port", "WAF PORT", 78),
            ("connection", "BACKEND", 92),
            ("protection", "PROTECTION", 180),
            ("inspected", "INSPECTED", 80),
            ("blocked", "BLOCKED", 70),
        ):
            self.apps_table.heading(column, text=heading)
            self.apps_table.column(
                column,
                width=width,
                minwidth=55,
                stretch=column in {"backend", "protection"},
            )
        self._configure_application_status_tags()
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.apps_table.yview)
        self.apps_table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.apps_table.pack(fill="both", expand=True)
        self.apps_table.bind("<Double-1>", lambda _event: self._monitor_application())

    def _refresh_applications_table(self) -> None:
        if not hasattr(self, "apps_table"):
            return
        selected = self.apps_table.selection()
        selected_id = selected[0] if selected else None
        needle = self._apps_filter_var.get().strip().casefold()
        for item in self.apps_table.get_children():
            self.apps_table.delete(item)
        for application in self.application_registry.list_applications():
            searchable = " ".join(
                (
                    str(application["name"]),
                    str(application["backend_url"]),
                    " ".join(application["hostnames"]),
                    str(application["connection_status"]),
                    str(application["protection_status"]),
                )
            ).casefold()
            if needle and needle not in searchable:
                continue
            stats = application["stats"]
            status = str(application["protection_status"])
            if status == "Protected":
                status = "Protected · inspected"
            if application["log_error"]:
                status += " · EVENT LOG ERROR"
            status_tag = (
                "protected"
                if application["is_protected"]
                else "listening"
                if status.startswith("Listening")
                else "stopped"
            )
            self.apps_table.insert(
                "",
                "end",
                iid=str(application["id"]),
                values=(
                    application["name"],
                    application["backend_url"],
                    application["listen_port"],
                    application["connection_status"],
                    status,
                    stats["inspected"],
                    application["recorded_attack_count"],
                ),
                tags=(status_tag,),
            )
        if selected_id and self.apps_table.exists(selected_id):
            self.apps_table.selection_set(selected_id)

    def _configure_application_status_tags(self) -> None:
        if not hasattr(self, "apps_table"):
            return
        colors = THEMES[self._theme_name]
        self.apps_table.tag_configure("protected", foreground=colors["good"])
        self.apps_table.tag_configure("listening", foreground=colors["warn"])
        self.apps_table.tag_configure("stopped", foreground=colors["fg_muted"])

    def _scheduled_applications_refresh(self) -> None:
        self._applications_refresh_id = None
        self._refresh_applications_table()
        if hasattr(self, "apps_table") and self.root.winfo_exists():
            self._applications_refresh_id = self.root.after(
                250,
                self._scheduled_applications_refresh,
            )

    def _selected_application_id(self) -> str | None:
        selection = self.apps_table.selection()
        return selection[0] if selection else None

    def _selected_application(self) -> ApplicationView | None:
        app_id = self._selected_application_id()
        if app_id is None:
            messagebox.showinfo(
                "Select an application",
                "Choose an application from the registry first.",
                parent=self.root,
            )
            return None
        return next(
            (
                app
                for app in self.application_registry.list_applications()
                if app["id"] == app_id
            ),
            None,
        )

    def _confirm_application_action(self, title: str, message: str) -> bool:
        return messagebox.askyesno(title, message, parent=self.root)

    def _add_application(self) -> None:
        self._open_application_form()

    def _edit_application(self) -> None:
        application = self._selected_application()
        if application is not None:
            self._open_application_form(application)

    def _open_application_form(self, application: ApplicationView | None = None) -> None:
        editing = application is not None
        window = tk.Toplevel(self.root)
        window.title("Edit Application" if editing else "Add Application")
        window.transient(self.root)
        window.geometry("640x430")
        window.configure(bg=THEMES[self._theme_name]["bg"])
        window.grab_set()

        name_var = tk.StringVar(value=application["name"] if application else "")
        backend_var = tk.StringVar(
            value=application["backend_url"]
            if application
            else "http://127.0.0.1:8000"
        )
        port_var = tk.StringVar(
            value=str(application["listen_port"]) if application else "8080"
        )
        hostnames_var = tk.StringVar(
            value=", ".join(application["hostnames"]) if application else ""
        )
        cert_var = tk.StringVar(
            value=application["tls_certfile"] or "" if application else ""
        )
        key_var = tk.StringVar(
            value=application["tls_keyfile"] or "" if application else ""
        )
        authorized_var = tk.BooleanVar(value=True)

        form = tk.Frame(window, padx=20, pady=18)
        self._register(form, "bg")
        form.pack(fill="both", expand=True)
        form.columnconfigure(1, weight=1)
        fields = (
            ("Application name", name_var),
            ("Backend URL", backend_var),
            ("WAF listen port", port_var),
            ("Additional accepted hostnames", hostnames_var),
            ("TLS certificate (optional)", cert_var),
            ("TLS private key (optional)", key_var),
        )
        for row, (label, variable) in enumerate(fields):
            label_widget = self._register(
                tk.Label(form, text=label, anchor="w"),
                "bg",
            )
            self._set_foreground(label_widget, "fg_dim")
            label_widget.grid(row=row, column=0, sticky="w", padx=(0, 12), pady=6)
            entry = ttk.Entry(form, textvariable=variable)
            entry.grid(row=row, column=1, sticky="ew", pady=6)
            if row in {4, 5}:
                ttk.Button(
                    form,
                    text="Browse",
                    command=lambda target=variable: self._browse_certificate(target),
                ).grid(row=row, column=2, padx=(8, 0), pady=6)
        auth_check = ttk.Checkbutton(
            form,
            text="I confirm I am authorized to proxy this application.",
            variable=authorized_var,
        )
        auth_check.grid(row=6, column=0, columnspan=3, sticky="w", pady=(10, 4))
        hint = self._register(
            tk.Label(
                form,
                text=(
                    "One fixed backend is mapped to this unique local port. Host headers "
                    "cannot select or change the destination."
                ),
                anchor="w",
                justify="left",
                wraplength=580,
            ),
            "bg",
        )
        self._set_foreground(hint, "fg_muted")
        hint.grid(row=7, column=0, columnspan=3, sticky="ew", pady=(2, 8))

        def save() -> None:
            try:
                listen_port = int(port_var.get().strip())
            except ValueError:
                messagebox.showerror(
                    "Invalid WAF port",
                    "Enter a whole number from 1 to 65535.",
                    parent=window,
                )
                return
            data: dict[str, object] = {
                "name": name_var.get().strip(),
                "backend_url": backend_var.get().strip(),
                "hostnames": [
                    hostname.strip()
                    for hostname in re.split(r"[\n,]", hostnames_var.get())
                    if hostname.strip()
                ],
                "listen_port": listen_port,
                "authorized": authorized_var.get(),
                "tls_certfile": cert_var.get().strip() or None,
                "tls_keyfile": key_var.get().strip() or None,
            }
            if not self._confirm_application_action(
                "Confirm authorized application",
                "Confirm that you own or are authorized to proxy this application. "
                "This registers a fixed backend mapping; it does not yet activate protection.",
            ):
                return
            try:
                if application is not None:
                    self.application_registry.update_application(
                        application["id"],
                        data,
                        confirmed=True,
                    )
                else:
                    self.application_registry.add_application(data, confirmed=True)
            except (OSError, PermissionError, RuntimeError, ValueError) as exc:
                messagebox.showerror("Could not save application", str(exc), parent=window)
                return
            self._refresh_applications_table()
            window.destroy()

        buttons = tk.Frame(form)
        self._register(buttons, "bg")
        buttons.grid(row=8, column=0, columnspan=3, sticky="e", pady=(10, 0))
        ttk.Button(buttons, text="Cancel", command=window.destroy).pack(side="right")
        ttk.Button(
            buttons,
            text="Save application",
            style="Accent.TButton",
            command=save,
        ).pack(side="right", padx=(0, 8))

    @staticmethod
    def _browse_certificate(variable: tk.StringVar) -> None:
        filename = filedialog.askopenfilename(
            title="Select TLS certificate or private key",
            filetypes=(("PEM files", "*.pem *.crt *.key"), ("All files", "*.*")),
        )
        if filename:
            variable.set(filename)

    def _connect_application(self) -> None:
        application = self._selected_application()
        if application is None:
            return
        if not self._confirm_application_action(
            "Test backend connection",
            "Test a TCP connection (and TLS certificate validation for HTTPS) to the "
            "registered backend? This does not start WAF protection.",
        ):
            return
        try:
            status = self.application_registry.test_connection(
                str(application["id"]),
                confirmed=True,
            )
        except (OSError, PermissionError, ValueError) as exc:
            messagebox.showerror("Backend connection failed", str(exc), parent=self.root)
        else:
            self.bottom_status.configure(
                text=f"{application['name']} backend connection: {status}"
            )
        self._refresh_applications_table()

    def _start_application_protection(self) -> None:
        application = self._selected_application()
        if application is None:
            return
        if not self._confirm_application_action(
            "Start WAF protection",
            f"Start the RIZVI WAF reverse proxy for {application['name']} on "
            f"127.0.0.1:{application['listen_port']}? The backend is fixed to "
            f"{application['backend_url']}. Protection will remain pending until traffic "
            "has passed through inspection.",
        ):
            return
        try:
            port = self.application_registry.start_protection(
                str(application["id"]),
                confirmed=True,
            )
        except (OSError, PermissionError, RuntimeError, ValueError) as exc:
            messagebox.showerror("Could not start protection", str(exc), parent=self.root)
            return
        self.bottom_status.configure(
            text=f"{application['name']} listener started on 127.0.0.1:{port}; awaiting inspected traffic"
        )
        self._refresh_applications_table()

    def _stop_application_protection(self) -> None:
        application = self._selected_application()
        if application is None:
            return
        if not self._confirm_application_action(
            "Stop WAF protection",
            f"Stop the WAF listener for {application['name']}?",
        ):
            return
        try:
            self.application_registry.stop_protection(
                str(application["id"]),
                confirmed=True,
            )
        except (OSError, PermissionError, RuntimeError, ValueError) as exc:
            messagebox.showerror("Could not stop protection", str(exc), parent=self.root)
            return
        self._refresh_applications_table()

    def _disconnect_application(self) -> None:
        application = self._selected_application()
        if application is None:
            return
        if not self._confirm_application_action(
            "Disconnect application",
            f"Disconnect {application['name']} and stop its listener if running? "
            "Its local event log will be retained.",
        ):
            return
        try:
            self.application_registry.disconnect(
                str(application["id"]),
                confirmed=True,
            )
        except (OSError, PermissionError, RuntimeError, ValueError) as exc:
            messagebox.showerror("Could not disconnect application", str(exc), parent=self.root)
            return
        self._refresh_applications_table()

    def _manage_application_rules(self) -> None:
        application = self._selected_application()
        if application is None:
            return
        window = tk.Toplevel(self.root)
        window.title(f"Manage WAF Rules · {application['name']}")
        window.transient(self.root)
        window.geometry("820x780")
        window.configure(bg=THEMES[self._theme_name]["bg"])
        window.grab_set()
        form = tk.Frame(window, padx=16, pady=14)
        self._register(form, "bg")
        form.pack(fill="both", expand=True)
        form.columnconfigure(1, weight=1)

        threshold_var = tk.StringVar(value=str(application["block_threshold"]))
        window_var = tk.StringVar(value=str(application["rate_limit_window_seconds"]))
        limit_var = tk.StringVar(value=str(application["rate_limit_max_requests"]))
        self._application_form_row(form, 0, "Block threshold", threshold_var)
        self._application_form_row(form, 1, "Rate window (seconds)", window_var)
        self._application_form_row(form, 2, "Requests per client/window", limit_var)

        rule_frame = tk.Frame(form)
        self._register(rule_frame, "panel")
        rule_frame.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=8)
        rule_frame.columnconfigure(0, weight=1)
        rule_vars: dict[str, tk.BooleanVar] = {}
        weight_vars: dict[str, tk.StringVar] = {}
        for row, rule in enumerate(RULES):
            enabled = tk.BooleanVar(value=rule.id in application["enabled_rule_ids"])
            weight = tk.StringVar(
                value=str(application["rule_weights"][rule.id])
            )
            rule_vars[rule.id] = enabled
            weight_vars[rule.id] = weight
            ttk.Checkbutton(
                rule_frame,
                text=f"{rule.id} · {rule.name}",
                variable=enabled,
            ).grid(row=row, column=0, sticky="w", padx=8, pady=2)
            ttk.Spinbox(
                rule_frame,
                from_=1,
                to=100,
                width=6,
                textvariable=weight,
            ).grid(row=row, column=1, padx=8, pady=2)

        allow_var = tk.StringVar(value=", ".join(application["allowlist_ips"]))
        block_var = tk.StringVar(value=", ".join(application["blocklist_ips"]))
        bypass_var = tk.StringVar(value=", ".join(application["path_bypasses"]))
        custom_text = tk.Text(form, height=5, wrap="word")
        custom_text.insert(
            "1.0",
            "\n".join(
                f"{name} = {literal}"
                for name, literal in self._custom_rules_for_app(application)
            ),
        )
        self._application_form_row(form, 4, "Allowlisted IP/CIDRs", allow_var)
        self._application_form_row(form, 5, "Blocked IP/CIDRs", block_var)
        self._application_form_row(form, 6, "Exact path bypasses", bypass_var)
        custom_label = self._register(
            tk.Label(
                form,
                text="Custom literal rules (one name = literal per line)",
                anchor="w",
            ),
            "bg",
        )
        self._set_foreground(custom_label, "fg_dim")
        custom_label.grid(row=7, column=0, sticky="nw", padx=(0, 12), pady=5)
        custom_text.grid(row=7, column=1, sticky="ew", pady=5)

        def split_values(value: str) -> list[str]:
            return [item.strip() for item in re.split(r"[\n,]", value) if item.strip()]

        def apply() -> None:
            try:
                enabled_ids = [rule_id for rule_id, var in rule_vars.items() if var.get()]
                weights = {
                    rule_id: int(var.get())
                    for rule_id, var in weight_vars.items()
                }
                custom_rules: list[dict[str, str]] = []
                for line in custom_text.get("1.0", "end").splitlines():
                    if not line.strip():
                        continue
                    if "=" not in line:
                        raise ValueError(f"Custom rule must use name = literal: {line!r}")
                    rule_name, literal = line.split("=", 1)
                    custom_rules.append(
                        {"name": rule_name.strip(), "pattern": literal.strip()}
                    )
                changes: dict[str, object] = {
                    "enabled_rule_ids": enabled_ids,
                    "rule_weights": weights,
                    "block_threshold": int(threshold_var.get()),
                    "rate_limit_window_seconds": int(window_var.get()),
                    "rate_limit_max_requests": int(limit_var.get()),
                    "allowlist_ips": split_values(allow_var.get()),
                    "blocklist_ips": split_values(block_var.get()),
                    "path_bypasses": split_values(bypass_var.get()),
                    "custom_rules": custom_rules,
                }
            except ValueError as exc:
                messagebox.showerror("Invalid WAF settings", str(exc), parent=window)
                return
            if not self._confirm_application_action(
                "Apply application security policy",
                "Apply these per-application inspection, access-list, and rate-limit settings?",
            ):
                return
            try:
                self.application_registry.update_security(
                    str(application["id"]),
                    changes,
                    confirmed=True,
                )
            except (OSError, PermissionError, RuntimeError, ValueError) as exc:
                messagebox.showerror("Could not update WAF settings", str(exc), parent=window)
                return
            window.destroy()

        buttons = tk.Frame(form)
        self._register(buttons, "bg")
        buttons.grid(row=8, column=0, columnspan=2, sticky="e", pady=(10, 0))
        ttk.Button(buttons, text="Cancel", command=window.destroy).pack(side="right")
        ttk.Button(
            buttons,
            text="Apply settings",
            style="Accent.TButton",
            command=apply,
        ).pack(side="right", padx=(0, 8))

    @staticmethod
    def _custom_rules_for_app(application: ApplicationView) -> list[tuple[str, str]]:
        return [
            (str(item["name"]), str(item["pattern"]))
            for item in application["custom_rules"]
        ]

    def _application_form_row(
        self,
        parent: tk.Frame,
        row: int,
        label: str,
        variable: tk.StringVar,
    ) -> None:
        label_widget = self._register(
            tk.Label(parent, text=label, anchor="w"),
            "bg",
        )
        self._set_foreground(label_widget, "fg_dim")
        label_widget.grid(row=row, column=0, sticky="w", padx=(0, 12), pady=5)
        ttk.Entry(parent, textvariable=variable).grid(
            row=row,
            column=1,
            sticky="ew",
            pady=5,
        )

    def _monitor_application(self) -> None:
        self._open_application_monitor(attacks_only=False)

    def _view_application_attacks(self) -> None:
        self._open_application_monitor(attacks_only=True)

    def _open_application_monitor(self, *, attacks_only: bool) -> None:
        application = self._selected_application()
        if application is None:
            return
        app_id = str(application["id"])
        title = "Detected attacks" if attacks_only else "Application monitor"
        window = tk.Toplevel(self.root)
        window.title(f"{title} · {application['name']}")
        window.transient(self.root)
        window.geometry("900x540")
        window.configure(bg=THEMES[self._theme_name]["bg"])
        summary = self._register(
            tk.Label(window, text="", anchor="w", padx=14, pady=10),
            "bg",
        )
        self._set_foreground(summary, "fg")
        summary.pack(fill="x")
        columns = ("time", "action", "method", "path", "client", "status", "rule")
        table = ttk.Treeview(window, columns=columns, show="headings")
        for column, heading, width in (
            ("time", "TIME", 82),
            ("action", "ACTION", 88),
            ("method", "METHOD", 72),
            ("path", "PATH", 240),
            ("client", "CLIENT", 120),
            ("status", "STATUS", 68),
            ("rule", "RULE / RESULT", 210),
        ):
            table.heading(column, text=heading)
            table.column(column, width=width, stretch=column in {"path", "rule"})
        scrollbar = ttk.Scrollbar(window, orient="vertical", command=table.yview)
        table.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        table.pack(fill="both", expand=True, padx=14, pady=(0, 14))

        def refresh() -> None:
            if not window.winfo_exists():
                return
            current = next(
                (
                    value
                    for value in self.application_registry.list_applications()
                    if value["id"] == app_id
                ),
                None,
            )
            if current is None:
                window.destroy()
                return
            stats = current["stats"]
            summary.configure(
                text=(
                    f"{current['name']}  ·  {current['protection_status']}  ·  "
                    f"Inspected {stats['inspected']}  ·  Allowed {stats['allowed']}  ·  "
                    f"Blocked {stats['blocked']}  ·  Backend {current['connection_status']}"
                    + (
                        f"  ·  {current['log_error']}"
                        if current["log_error"]
                        else ""
                    )
                )
            )
            for item in table.get_children():
                table.delete(item)
            for event in self.application_registry.application_events(
                app_id,
                attacks_only=attacks_only,
            ):
                table.insert(
                    "",
                    "end",
                    values=(
                        event.get("timestamp", ""),
                        event.get("action", ""),
                        event.get("method", ""),
                        event.get("path", ""),
                        event.get("client", ""),
                        event.get("status", ""),
                        event.get("detail", ""),
                    ),
                )
            window.after(250, refresh)

        refresh()

    def _generate_application_report(self) -> None:
        application = self._selected_application()
        if application is None:
            return
        filename = filedialog.asksaveasfilename(
            parent=self.root,
            title="Generate application security report",
            initialfile=f"{application['name'].replace(' ', '_')}_waf_report.json",
            defaultextension=".json",
            filetypes=(("JSON report", "*.json"),),
        )
        if not filename:
            return
        try:
            report = self.application_registry.generate_report(
                str(application["id"]),
                Path(filename),
            )
        except (OSError, PermissionError, ValueError) as exc:
            messagebox.showerror("Report generation failed", str(exc), parent=self.root)
            return
        self.bottom_status.configure(
            text=f"Security report generated · {report['recorded_event_count']} recorded events"
        )

    def _build_management_page(self, page: tk.Frame) -> None:
        self._page_heading(
            page,
            "WAF management",
            "Changes apply to new requests immediately and are saved for the next launch.",
        )
        self.management_tabs = ttk.Notebook(page)
        self.management_tabs.pack(fill="both", expand=True)

        rules_page = tk.Frame(self.management_tabs, padx=12, pady=12)
        access_page = tk.Frame(self.management_tabs, padx=12, pady=12)
        self.management_tabs.add(rules_page, text="Inspection rules")
        self.management_tabs.add(access_page, text="Access lists")
        self._build_rule_controls(rules_page)
        self._build_access_controls(access_page)

    def _build_rule_controls(self, page: tk.Frame) -> None:
        threshold_frame = tk.Frame(page, padx=12, pady=10)
        self._register(threshold_frame, "panel")
        threshold_frame.pack(fill="x", pady=(0, 10))
        threshold_label = self._register(
            tk.Label(
                threshold_frame,
                text="BLOCK THRESHOLD",
                font=("Segoe UI", 9, "bold"),
            ),
            "panel",
        )
        self._set_foreground(threshold_label, "fg")
        threshold_label.pack(side="left")
        self.threshold_var = tk.StringVar(value=str(self._block_threshold))
        ttk.Spinbox(
            threshold_frame,
            from_=1,
            to=100,
            width=7,
            textvariable=self.threshold_var,
        ).pack(side="left", padx=(12, 8))
        ttk.Button(
            threshold_frame,
            text="Apply threshold",
            command=self._apply_block_threshold,
        ).pack(side="left")
        threshold_hint = self._register(
            tk.Label(
                threshold_frame,
                text="Matched rule weights are summed. Lower thresholds block more.",
                font=("Segoe UI", 8),
            ),
            "panel",
        )
        self._set_foreground(threshold_hint, "fg_muted")
        threshold_hint.pack(side="left", padx=(14, 0))

        table_frame = tk.Frame(page, padx=12, pady=10)
        self._register(table_frame, "panel")
        table_frame.pack(fill="both", expand=True, pady=(0, 10))
        table_title = self._register(
            tk.Label(
                table_frame,
                text=f"INSPECTION RULES  ·  {len(RULES)}",
                font=("Segoe UI", 9, "bold"),
            ),
            "panel",
        )
        self._set_foreground(table_title, "fg")
        table_title.pack(anchor="w", pady=(0, 8))

        self.rules_table = ttk.Treeview(
            table_frame,
            columns=("id", "name", "enabled", "weight"),
            show="headings",
            selectmode="browse",
        )
        for column, heading, width in (
            ("id", "RULE ID", 100),
            ("name", "DETECTION", 360),
            ("enabled", "ENABLED", 100),
            ("weight", "WEIGHT", 90),
        ):
            self.rules_table.heading(column, text=heading)
            self.rules_table.column(
                column,
                width=width,
                minwidth=60,
                stretch=column == "name",
                anchor="w" if column == "name" else "center",
            )
        rules_scrollbar = ttk.Scrollbar(
            table_frame, orient="vertical", command=self.rules_table.yview
        )
        self.rules_table.configure(yscrollcommand=rules_scrollbar.set)
        rules_scrollbar.pack(side="right", fill="y")
        self.rules_table.pack(fill="both", expand=True)
        self.rules_table.bind("<<TreeviewSelect>>", self._on_rule_selected)

        editor = tk.Frame(page, padx=12, pady=10)
        self._register(editor, "panel")
        editor.pack(fill="x")
        self.selected_rule_label = self._register(
            tk.Label(editor, text="Select a rule to edit", font=("Segoe UI", 9, "bold")),
            "panel",
        )
        self._set_foreground(self.selected_rule_label, "fg")
        self.selected_rule_label.grid(row=0, column=0, sticky="w", padx=(0, 18))
        self.rule_enabled_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            editor,
            text="Enabled",
            variable=self.rule_enabled_var,
        ).grid(row=0, column=1, padx=(0, 14))
        ttk.Label(editor, text="Weight (1–100)").grid(row=0, column=2, sticky="e")
        self.rule_weight_var = tk.StringVar()
        ttk.Spinbox(
            editor,
            from_=1,
            to=100,
            width=7,
            textvariable=self.rule_weight_var,
        ).grid(row=0, column=3, padx=(8, 14))
        self.apply_rule_button = ttk.Button(
            editor,
            text="Apply selected rule",
            command=self._apply_selected_rule,
            state="disabled",
        )
        self.apply_rule_button.grid(row=0, column=4, sticky="e")
        editor.columnconfigure(0, weight=1)

        self._refresh_rules_table()

    def _build_access_controls(self, page: tk.Frame) -> None:
        note = self._register(
            tk.Label(
                page,
                text=(
                    "Blocked IPs take precedence. Allowlisted IPs and exact path bypasses "
                    "skip heuristic inspection, not method, size, or rate checks."
                ),
                font=("Segoe UI", 9),
                anchor="w",
                justify="left",
                wraplength=800,
            ),
            "bg",
        )
        self._set_foreground(note, "fg_dim")
        note.pack(fill="x", pady=(0, 12))

        groups = tk.Frame(page)
        self._register(groups, "bg")
        groups.pack(fill="both", expand=True)
        for column in range(3):
            groups.columnconfigure(column, weight=1, uniform="access")
        self.access_entries: dict[str, ttk.Entry] = {}
        self.access_tables: dict[str, ttk.Treeview] = {}
        self._access_hints: dict[str, str] = {}
        self._build_access_group(
            groups, 0, "Allowlisted IPs / CIDRs", "allow_ip", "e.g. 192.168.1.10 or 10.0.0.0/8"
        )
        self._build_access_group(
            groups, 1, "Blocked IPs / CIDRs", "block_ip", "e.g. 203.0.113.8"
        )
        self._build_access_group(
            groups, 2, "Exact path bypasses", "path", "e.g. /health"
        )
        self._refresh_access_tables()

    def _build_access_group(
        self,
        parent: tk.Frame,
        column: int,
        title: str,
        kind: str,
        placeholder: str,
    ) -> None:
        group = tk.Frame(parent, padx=10, pady=10)
        self._register(group, "panel")
        group.grid(row=0, column=column, sticky="nsew", padx=(0, 8))
        group.columnconfigure(0, weight=1)
        heading = self._register(
            tk.Label(group, text=title, font=("Segoe UI", 9, "bold"), anchor="w"),
            "panel",
        )
        self._set_foreground(heading, "fg")
        heading.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 8))

        entry = ttk.Entry(group)
        entry.grid(row=1, column=0, sticky="ew", padx=(0, 6), pady=(0, 8))
        entry.insert(0, placeholder)
        entry.bind("<FocusIn>", lambda _event, e=entry, p=placeholder: self._clear_hint(e, p))
        entry.bind("<Return>", lambda _event, k=kind: self._add_access_value(k))
        self.access_entries[kind] = entry
        self._access_hints[kind] = placeholder
        ttk.Button(
            group,
            text="Add",
            command=lambda k=kind: self._add_access_value(k),
        ).grid(row=1, column=1, sticky="e", pady=(0, 8))

        table = ttk.Treeview(group, columns=("value",), show="headings", height=12)
        table.heading("value", text="VALUE")
        table.column("value", width=220, minwidth=80, stretch=True)
        scrollbar = ttk.Scrollbar(group, orient="vertical", command=table.yview)
        table.configure(yscrollcommand=scrollbar.set)
        table.grid(row=2, column=0, sticky="nsew")
        scrollbar.grid(row=2, column=1, sticky="ns")
        self.access_tables[kind] = table
        group.rowconfigure(2, weight=1)
        ttk.Button(
            group,
            text="Remove selected",
            command=lambda k=kind: self._remove_access_value(k),
        ).grid(row=3, column=0, sticky="w", pady=(8, 0))

    @staticmethod
    def _clear_hint(entry: ttk.Entry, hint: str) -> None:
        if entry.get() == hint:
            entry.delete(0, "end")

    def _refresh_rules_table(self) -> None:
        if not hasattr(self, "rules_table"):
            return
        selected = self.rules_table.selection()
        for item in self.rules_table.get_children():
            self.rules_table.delete(item)
        for rule in RULES:
            self.rules_table.insert(
                "",
                "end",
                iid=rule.id,
                values=(
                    rule.id,
                    rule.name,
                    "Yes" if rule.id in self._enabled_rule_ids else "No",
                    self._rule_weights[rule.id],
                ),
            )
        if selected and selected[0] in {rule.id for rule in RULES}:
            self.rules_table.selection_set(selected[0])
            self.rules_table.focus(selected[0])

    def _on_rule_selected(self, _event: tk.Event) -> None:
        selected = self.rules_table.selection()
        if not selected:
            return
        rule_id = selected[0]
        rule = next(rule for rule in RULES if rule.id == rule_id)
        self.selected_rule_label.configure(text=f"{rule.id} · {rule.name}")
        self.rule_enabled_var.set(rule_id in self._enabled_rule_ids)
        self.rule_weight_var.set(str(self._rule_weights[rule_id]))
        self.apply_rule_button.configure(state="normal")

    def _apply_selected_rule(self) -> None:
        selected = self.rules_table.selection()
        if not selected:
            return
        rule_id = selected[0]
        try:
            weight = int(self.rule_weight_var.get())
        except ValueError:
            messagebox.showerror("Invalid rule weight", "Enter a whole number from 1 to 100.", parent=self.root)
            return

        enabled_ids = set(self._enabled_rule_ids)
        if self.rule_enabled_var.get():
            enabled_ids.add(rule_id)
        else:
            self._config_load_error = None
            enabled_ids.discard(rule_id)
        weights = dict(self._rule_weights)
        weights[rule_id] = weight
        self._commit_rule_configuration(enabled_ids, weights, self._block_threshold)

    def _apply_block_threshold(self) -> None:
        try:
            threshold = int(self.threshold_var.get())
        except ValueError:
            messagebox.showerror(
                "Invalid threshold",
                "Enter a whole number from 1 to 100.",
                parent=self.root,
            )
            return
        self._commit_rule_configuration(
            set(self._enabled_rule_ids),
            dict(self._rule_weights),
            threshold,
        )

    def _commit_rule_configuration(
        self,
        enabled_ids: set[str],
        weights: dict[str, int],
        threshold: int,
    ) -> None:
        if not enabled_ids:
            messagebox.showerror(
                "No active rules",
                "At least one inspection rule must remain enabled.",
                parent=self.root,
            )
            self.rule_enabled_var.set(True)
            return
        if not 1 <= threshold <= 100 or any(
            not 1 <= weight <= 100 for weight in weights.values()
        ):
            messagebox.showerror(
                "Invalid rule configuration",
                "Threshold and rule weights must be from 1 to 100.",
                parent=self.root,
            )
            return
        try:
            if self.proxy is not None:
                self.proxy.configure_rules(enabled_ids, weights, threshold)
        except ValueError as exc:
            messagebox.showerror("Could not update rules", str(exc), parent=self.root)
            return

        self._enabled_rule_ids = enabled_ids
        self._rule_weights = weights
        self._block_threshold = threshold
        self.threshold_var.set(str(threshold))
        self._refresh_rules_table()
        self._save_configuration_with_feedback("WAF inspection rules updated")

    def _access_values(self, kind: str) -> list[str]:
        if kind == "allow_ip":
            return self._allowlist_ips
        if kind == "block_ip":
            return self._blocklist_ips
        return self._path_bypasses

    def _refresh_access_tables(self) -> None:
        for kind, table in getattr(self, "access_tables", {}).items():
            for item in table.get_children():
                table.delete(item)
            for value in self._access_values(kind):
                table.insert("", "end", values=(value,))

    def _add_access_value(self, kind: str) -> None:
        entry = self.access_entries[kind]
        raw = entry.get().strip()
        if not raw or raw == self._access_hints[kind]:
            return
        try:
            if kind in {"allow_ip", "block_ip"}:
                value = str(ipaddress.ip_network(raw, strict=False))
            else:
                value = self._normalise_path_bypass(raw)
        except ValueError as exc:
            messagebox.showerror("Invalid access-list entry", str(exc), parent=self.root)
            return
        values = self._access_values(kind)
        if value in values:
            return
        updated = [*values, value]
        allowlist_ips = updated if kind == "allow_ip" else self._allowlist_ips
        blocklist_ips = updated if kind == "block_ip" else self._blocklist_ips
        path_bypasses = updated if kind == "path" else self._path_bypasses
        self._commit_access_lists(allowlist_ips, blocklist_ips, path_bypasses)
        entry.delete(0, "end")

    def _remove_access_value(self, kind: str) -> None:
        table = self.access_tables[kind]
        selected = table.selection()
        if not selected:
            return
        value = str(table.item(selected[0], "values")[0])
        updated = [item for item in self._access_values(kind) if item != value]
        allowlist_ips = updated if kind == "allow_ip" else self._allowlist_ips
        blocklist_ips = updated if kind == "block_ip" else self._blocklist_ips
        path_bypasses = updated if kind == "path" else self._path_bypasses
        self._commit_access_lists(allowlist_ips, blocklist_ips, path_bypasses)

    def _commit_access_lists(
        self,
        allowlist_ips: list[str],
        blocklist_ips: list[str],
        path_bypasses: list[str],
    ) -> None:
        path_patterns = tuple(
            re.compile(rf"^{re.escape(path)}$")
            for path in path_bypasses
        )
        try:
            if self.proxy is not None:
                self.proxy.configure_access_lists(
                    allowlist_ips,
                    blocklist_ips,
                    path_patterns,
                )
        except ValueError as exc:
            messagebox.showerror("Could not update access lists", str(exc), parent=self.root)
            return

        self._allowlist_ips = list(allowlist_ips)
        self._blocklist_ips = list(blocklist_ips)
        self._path_bypasses = list(path_bypasses)
        self._refresh_access_tables()
        self._save_configuration_with_feedback("WAF access lists updated")

    def _build_stats_page(self, page: tk.Frame) -> None:
        self._page_heading(
            page,
            "Traffic statistics",
            "Live counters and per-second traffic over the most recent 60 seconds.",
        )
        cards = tk.Frame(page)
        self._register(cards, "bg")
        cards.pack(fill="x", pady=(0, 16))
        self._stat_card(cards, "ALLOWED", "0", "good", "allowed")
        self._stat_card(cards, "BLOCKED", "0", "bad", "blocked")
        self._stat_card(cards, "TOTAL INSPECTED", "0", "accent", "total")
        self._stat_card(cards, "BLOCK RATE", "0%", "warn", "rate")

        chart_frame = tk.Frame(page, padx=14, pady=12)
        self._register(chart_frame, "panel")
        chart_frame.pack(fill="both", expand=True)
        chart_header = tk.Frame(chart_frame)
        self._register(chart_header, "panel")
        chart_header.pack(fill="x", pady=(0, 8))
        chart_title = self._register(
            tk.Label(
                chart_header,
                text="REQUESTS PER SECOND  ·  LAST 60 SECONDS",
                font=("Segoe UI", 9, "bold"),
            ),
            "panel",
        )
        self._set_foreground(chart_title, "fg")
        chart_title.pack(side="left")
        allowed_legend = self._register(
            tk.Label(chart_header, text="● Allowed", font=("Segoe UI", 8)),
            "panel",
        )
        self._set_foreground(allowed_legend, "good")
        allowed_legend.pack(side="right", padx=(12, 4))
        blocked_legend = self._register(
            tk.Label(chart_header, text="● Blocked", font=("Segoe UI", 8)),
            "panel",
        )
        self._set_foreground(blocked_legend, "bad")
        blocked_legend.pack(side="right")
        self.stats_rate_label = self._register(
            tk.Label(chart_header, text="0.0 ev/s", font=("Segoe UI", 9, "bold")),
            "panel",
        )
        self._set_foreground(self.stats_rate_label, "accent")
        self.stats_rate_label.pack(side="right", padx=(0, 16))
        self.stats_chart = self._register(
            tk.Canvas(chart_frame, height=330, highlightthickness=0),
            "panel",
        )
        self.stats_chart.pack(fill="both", expand=True)
        self.stats_chart.bind("<Configure>", self._draw_traffic_chart)
        self.stats_chart.bind("<Map>", self._draw_traffic_chart)

    def _build_settings_page(self, page: tk.Frame) -> None:
        self._page_heading(
            page,
            "Settings",
            "Display and log controls are here; manage WAF rules and access lists on Manage.",
        )
        options = tk.Frame(page, padx=18, pady=16)
        self._register(options, "panel")
        options.pack(fill="x", pady=(0, 12))
        option_title = self._register(
            tk.Label(options, text="TRAFFIC DISPLAY", font=("Segoe UI", 9, "bold")),
            "panel",
        )
        self._set_foreground(option_title, "fg")
        option_title.pack(anchor="w", pady=(0, 10))
        ttk.Checkbutton(
            options,
            text="Auto-scroll newest events to the top",
            variable=self._autoscroll,
            command=self._on_autoscroll_toggle,
        ).pack(anchor="w", pady=4)
        ttk.Button(options, text="Clear traffic and reset counters", command=self._clear_log).pack(
            anchor="w", pady=(10, 4)
        )
        ttk.Button(options, text="Export visible traffic to CSV", command=self._export_csv).pack(
            anchor="w", pady=4
        )
        self._info_card(
            page,
            "NETWORK BINDING",
            "Local machine only",
            "The listener binds to 127.0.0.1 and does not accept connections from other "
            "devices on the network.",
        )
        self._info_card(
            page,
            "EVENT HISTORY",
            "In-memory, bounded log",
            "The table keeps up to 1,000 recent events. Export a CSV before clearing if "
            "you need to retain a copy.",
        )
        self._info_card(
            page,
            "WAF CONFIGURATION",
            "Saved locally",
            f"Rules and access lists are stored at {self._config_path}",
        )

    def _build_about_page(self, page: tk.Frame) -> None:
        self._page_heading(
            page,
            "About RIZVI WAF",
            "Manage and monitor authorized applications through isolated reverse-proxy listeners.",
        )
        self._info_card(
            page,
            "APPLICATION",
            "Multi-application Python WAF",
            "Each authorized application has a fixed backend, its own loopback listener, "
            "independent rules and limits, traffic statistics, and saved request events. "
            "Application listeners can use optional TLS.",
        )
        self._info_card(
            page,
            "IMPORTANT",
            "Local development protection",
            "Inspection is heuristic and can miss attacks or block normal requests. "
            "Listeners bind to loopback. Optional AWS WAF integration is separate and "
            "is not active unless its template is deployed to an ALB. Use a managed "
            "production WAF for internet-facing traffic.",
        )

    def _page_heading(self, page: tk.Frame, title: str, subtitle: str) -> None:
        heading = self._register(
            tk.Label(page, text=title, font=("Segoe UI", 18, "bold"), anchor="w"),
            "bg",
        )
        self._set_foreground(heading, "fg")
        heading.pack(fill="x", pady=(0, 4))
        description = self._register(
            tk.Label(
                page,
                text=subtitle,
                font=("Segoe UI", 9),
                anchor="w",
                justify="left",
                wraplength=760,
            ),
            "bg",
        )
        self._set_foreground(description, "fg_muted")
        description.pack(fill="x", pady=(0, 16))

    def _info_card(self, page: tk.Frame, eyebrow: str, title: str, description: str) -> None:
        card = tk.Frame(page, padx=16, pady=13)
        self._register(card, "panel")
        card.pack(fill="x", pady=(0, 10))
        label = self._register(
            tk.Label(card, text=eyebrow, font=("Segoe UI", 8, "bold"), anchor="w"),
            "panel",
        )
        self._set_foreground(label, "accent")
        label.pack(fill="x")
        title_label = self._register(
            tk.Label(card, text=title, font=("Segoe UI", 11, "bold"), anchor="w"),
            "panel",
        )
        self._set_foreground(title_label, "fg")
        title_label.pack(fill="x", pady=(4, 3))
        detail = self._register(
            tk.Label(
                card,
                text=description,
                font=("Segoe UI", 9),
                anchor="w",
                justify="left",
                wraplength=760,
            ),
            "panel",
        )
        self._set_foreground(detail, "fg_dim")
        detail.pack(fill="x")

    def _show_page(self, name: str) -> None:
        if name not in self.pages:
            return
        for page in self.pages.values():
            page.pack_forget()
        self.pages[name].pack(fill="both", expand=True)
        self._active_page = name
        self._update_nav_buttons()
        if name == "Stats":
            self._draw_traffic_chart()

    def _update_nav_buttons(self) -> None:
        if not hasattr(self, "_nav_buttons"):
            return
        t = THEMES[self._theme_name]
        for name, button in self._nav_buttons.items():
            selected = name == self._active_page
            button.configure(
                bg=t["selected"] if selected else t["panel"],
                fg=t["accent"] if selected else t["fg_dim"],
                activebackground=t["selected"],
                activeforeground=t["fg"],
            )

    # ------------------------------------------------------------------ #
    # Stat card helper
    # ------------------------------------------------------------------ #
    def _stat_card(
        self,
        parent: tk.Widget,
        title: str,
        value: str,
        color_role: str,
        metric: str | None = None,
    ) -> tk.Label:
        card = self._register(tk.Frame(parent, padx=18, pady=12), "panel")
        card.pack(side="left", fill="x", expand=True, padx=(0, 10))

        title_lbl = self._register(
            tk.Label(card, text=title, font=("Segoe UI", 8, "bold")), "panel"
        )
        self._set_foreground(title_lbl, "fg_dim")
        title_lbl.pack(anchor="w")

        value_lbl = self._register(
            tk.Label(card, text=value, font=("Segoe UI", 20, "bold")), "panel"
        )
        self._set_foreground(value_lbl, color_role)
        value_lbl.pack(anchor="w", pady=(3, 0))

        if metric is not None:
            self._stat_labels.setdefault(metric, []).append(value_lbl)
        return value_lbl

    def _set_metric(self, metric: str, value: str) -> None:
        for label in self._stat_labels.get(metric, []):
            label.configure(text=value)

    # ------------------------------------------------------------------ #
    # Keyboard & UI actions
    # ------------------------------------------------------------------ #
    def _bind_shortcuts(self) -> None:
        self.root.bind("<F5>", lambda _e: self._start())
        self.root.bind("<F6>", lambda _e: self._stop())
        self.root.bind("<Control-l>", lambda _e: self._clear_log())
        self.root.bind("<Control-f>", self._focus_search)
        self.root.bind("<Control-t>", lambda _e: self._toggle_theme())

    def _focus_search(self, _event: tk.Event | None = None) -> None:
        self._show_page("Traffic")
        self.search_entry.focus_set()

    def _on_autoscroll_toggle(self) -> None:
        self.bottom_status.configure(
            text="Auto-scroll: newest first" if self._autoscroll.get()
            else "Auto-scroll: append at bottom"
        )

    def _toggle_pause(self) -> None:
        self._paused = not self._paused
        self.pause_button.configure(text="▶  Resume" if self._paused else "⏸  Pause")
        self._update_status_pill()

    @staticmethod
    def _status_pill_state(
        proxy_running: bool,
        events_paused: bool,
        inspected_traffic_seen: bool,
    ) -> tuple[str, str]:
        if not proxy_running:
            return "STOPPED", "warn"
        if events_paused:
            return "LOG PAUSED", "accent"
        if inspected_traffic_seen:
            return "LOCAL ACTIVE", "good"
        return "LOCAL WAITING", "warn"

    def _update_status_pill(self) -> None:
        t = THEMES[self._theme_name]
        inspected_traffic_seen = (
            self.proxy is not None
            and not self._paused
            and self.proxy.stats()["inspected"] > 0
        )
        text, color_role = self._status_pill_state(
            self.proxy is not None,
            self._paused,
            inspected_traffic_seen,
        )
        dot, color = "●", t[color_role]
        self.status_dot.configure(text=dot, fg=color)
        self.status_label.configure(text=text)

    def _set_status_detail(self, text: str) -> None:
        self.status_detail.configure(text=text)

    # ------------------------------------------------------------------ #
    # Start / stop
    # ------------------------------------------------------------------ #
    def _start(self) -> None:
        if self.proxy is not None:
            return
        backend = self.backend_entry.get().strip()
        parsed = urlparse(backend)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            messagebox.showerror(
                "Invalid backend URL",
                "Backend URL must start with http:// or https:// and include a host.",
                parent=self.root,
            )
            return
        try:
            port = int(self.port_entry.get().strip())
            if not 1 <= port <= 65535:
                raise ValueError("Listen port must be between 1 and 65535.")
            proxy = WAFProxy(backend, port, self.events.put)
            proxy.configure_rules(
                self._enabled_rule_ids,
                self._rule_weights,
                self._block_threshold,
            )
            proxy.configure_access_lists(
                self._allowlist_ips,
                self._blocklist_ips,
                tuple(
                    re.compile(rf"^{re.escape(path)}$")
                    for path in self._path_bypasses
                ),
            )
            proxy.start()
            self.proxy = proxy
        except (ValueError, OSError) as exc:
            self.proxy = None
            messagebox.showerror("Could not start firewall", str(exc), parent=self.root)
            self._set_status_detail(f"Start failed: {exc}")
            return

        self.backend_entry.configure(state="disabled")
        self.port_entry.configure(state="disabled")
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self._started_at = time.monotonic()
        self._set_status_detail(f"Listening on http://127.0.0.1:{self.proxy.port}")
        self.bottom_status.configure(text=f"Firewall started — proxying to {backend}")
        self._update_status_pill()
        self._update_uptime()

    def _stop(self) -> None:
        if self.proxy is not None:
            self.proxy.stop()
            self.proxy = None
        self.backend_entry.configure(state="normal")
        self.port_entry.configure(state="normal")
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self._paused = False
        self.pause_button.configure(text="⏸  Pause")
        self._started_at = None
        self._set_status_detail("Proxy listens on 127.0.0.1 only")
        self.bottom_status.configure(text="Firewall stopped")
        self._update_status_pill()
        self._update_uptime()

    # ------------------------------------------------------------------ #
    # Event drain
    # ------------------------------------------------------------------ #
    def _queue_application_event(
        self,
        app_id: str,
        event: FirewallEvent,
    ) -> None:
        application_events = getattr(self, "application_events", None)
        if application_events is not None:
            application_events.put((app_id, event))

    def _drain_events(self) -> None:
        new_events: list[FirewallEvent] = []
        while True:
            try:
                new_events.append(self.events.get_nowait())
            except queue.Empty:
                break

        application_events = getattr(self, "application_events", None)
        if application_events is not None:
            while True:
                try:
                    _app_id, event = application_events.get_nowait()
                    new_events.append(event)
                except queue.Empty:
                    break

        if new_events:
            self._recent_timestamps.extend(time.time() for _ in new_events)

        if self._paused:
            self._pending_events.extend(new_events)
        else:
            events_to_ingest = self._pending_events + new_events
            self._pending_events.clear()
            for event in events_to_ingest:
                self._ingest_event(event)

        if application_events is not None and hasattr(self, "apps_table"):
            self._refresh_applications_table()

        self.root.after(100, self._drain_events)

    def _ingest_event(self, event: FirewallEvent) -> None:
        bucket = self._traffic_buckets.setdefault(int(time.monotonic()), [0, 0])
        if event.action == "BLOCKED":
            self.blocked_count += 1
            bucket[1] += 1
        else:
            self.allowed_count += 1
            bucket[0] += 1

        total = self.allowed_count + self.blocked_count
        rate = (self.blocked_count / total * 100) if total else 0
        self._set_metric("allowed", str(self.allowed_count))
        self._set_metric("blocked", str(self.blocked_count))
        self._set_metric("total", str(total))
        self._set_metric("rate", f"{rate:.1f}%")

        tag = "blocked" if event.action == "BLOCKED" else "allowed"
        values = (
            event.timestamp,
            event.action,
            event.method,
            event.path,
            event.client,
            event.status,
            event.detail,
        )

        if self._autoscroll.get():
            item = self.table.insert("", 0, values=values, tags=(tag,))
        else:
            item = self.table.insert("", "end", values=values, tags=(tag,))
        self._row_ids.append(item)

        if not self._row_matches_filter(values):
            self.table.detach(item)

        if len(self._row_ids) > 1000:
            for old in self._row_ids[:-1000]:
                self.table.delete(old)
            self._row_ids = self._row_ids[-1000:]
        self._update_status_pill()

    # ------------------------------------------------------------------ #
    # Filtering / sorting
    # ------------------------------------------------------------------ #
    def _row_matches_filter(self, values: tuple) -> bool:
        needle = self._filter_var.get().strip().lower()
        if not needle:
            return True
        return any(needle in str(v).lower() for v in values)

    def _apply_filter(self) -> None:
        needle = self._filter_var.get().strip().lower()
        ordered_ids = (
            reversed(self._row_ids) if self._autoscroll.get() else iter(self._row_ids)
        )
        index = 0
        for item in ordered_ids:
            values = self.table.item(item, "values")
            if not needle or any(needle in str(v).lower() for v in values):
                self.table.reattach(item, "", "end")
                self.table.move(item, "", index)
                index += 1
            else:
                self.table.detach(item)

    def _sort_column(self, column: str) -> None:
        data = [
            (self.table.set(item, column), item)
            for item in self.table.get_children("")
        ]
        data.sort(reverse=False)
        for index, (_, item) in enumerate(data):
            self.table.move(item, "", index)

    # ------------------------------------------------------------------ #
    # Throughput
    # ------------------------------------------------------------------ #
    def _update_throughput(self) -> None:
        now = time.time()
        cutoff = now - 5
        self._recent_timestamps = [t for t in self._recent_timestamps if t >= cutoff]
        rate = len(self._recent_timestamps) / 5.0
        self.throughput_label.configure(text=f"{rate:.1f} ev/s")
        self.stats_rate_label.configure(text=f"{rate:.1f} ev/s")
        current_second = int(time.monotonic())
        oldest_second = current_second - 59
        self._traffic_buckets = {
            second: counts
            for second, counts in self._traffic_buckets.items()
            if second >= oldest_second
        }
        if self._active_page == "Stats":
            self._draw_traffic_chart()
        self._update_uptime()
        self.root.after(1000, self._update_throughput)

    def _traffic_series(self, current_second: int) -> list[tuple[int, int, int]]:
        series: list[tuple[int, int, int]] = []
        for second in range(current_second - 59, current_second + 1):
            counts = self._traffic_buckets.get(second)
            series.append(
                (second, counts[0], counts[1]) if counts is not None
                else (second, 0, 0)
            )
        return series

    def _draw_traffic_chart(self, _event: tk.Event | None = None) -> None:
        if not hasattr(self, "stats_chart"):
            return
        canvas = self.stats_chart
        canvas.delete("all")
        width = max(canvas.winfo_width(), 480)
        height = max(canvas.winfo_height(), 240)
        left, right, top, bottom = 54, width - 18, 14, height - 34
        plot_width = right - left
        plot_height = bottom - top
        series = self._traffic_series(int(time.monotonic()))
        peak = max((allowed + blocked for _, allowed, blocked in series), default=0)
        colors = THEMES[self._theme_name]
        scale = max(peak, 1)

        if peak == 0:
            canvas.create_line(left, bottom, right, bottom, fill=colors["header"])
            canvas.create_text(
                left - 8,
                bottom,
                text="0",
                fill=colors["fg_dim"],
                anchor="e",
                font=("Segoe UI", 8),
            )
        else:
            for division in range(4):
                value = scale * division / 3
                y = bottom - plot_height * division / 3
                canvas.create_line(left, y, right, y, fill=colors["header"])
                canvas.create_text(
                    left - 8,
                    y,
                    text=f"{value:.1f}" if scale < 3 else f"{value:.0f}",
                    fill=colors["fg_dim"],
                    anchor="e",
                    font=("Segoe UI", 8),
                )

        if peak == 0:
            canvas.create_text(
                (left + right) / 2,
                (top + bottom) / 2,
                text="Waiting for traffic…",
                fill=colors["fg_muted"],
                font=("Segoe UI", 10),
            )
        else:
            slot_width = plot_width / len(series)
            bar_width = max(1, slot_width * 0.62)
            for index, (_, allowed, blocked) in enumerate(series):
                x_center = left + slot_width * (index + 0.5)
                allowed_height = plot_height * allowed / scale
                blocked_height = plot_height * blocked / scale
                canvas.create_rectangle(
                    x_center - bar_width / 2,
                    bottom - allowed_height,
                    x_center + bar_width / 2,
                    bottom,
                    fill=colors["good"],
                    outline="",
                )
                if blocked_height:
                    canvas.create_rectangle(
                        x_center - bar_width / 2,
                        bottom - allowed_height - blocked_height,
                        x_center + bar_width / 2,
                        bottom - allowed_height,
                        fill=colors["bad"],
                        outline="",
                    )

        for index, label in ((0, "60s ago"), (15, "45s"), (30, "30s"), (45, "15s"), (59, "now")):
            x = left + plot_width * index / (len(series) - 1)
            canvas.create_text(
                x,
                bottom + 18,
                text=label,
                fill=colors["fg_dim"],
                anchor="center",
                font=("Segoe UI", 8),
            )

    def _update_uptime(self) -> None:
        if self._started_at is None:
            elapsed = 0
        else:
            elapsed = max(0, int(time.monotonic() - self._started_at))
        hours, remainder = divmod(elapsed, 3600)
        minutes, seconds = divmod(remainder, 60)
        self.uptime_label.configure(
            text=f"Uptime {hours:02d}:{minutes:02d}:{seconds:02d}"
        )

    # ------------------------------------------------------------------ #
    # Clear / export
    # ------------------------------------------------------------------ #
    def _clear_log(self) -> None:
        for item in self._row_ids:
            self.table.delete(item)
        self._row_ids.clear()
        self._pending_events.clear()
        self.allowed_count = 0
        self.blocked_count = 0
        self._recent_timestamps.clear()
        self._traffic_buckets.clear()
        self._set_metric("allowed", "0")
        self._set_metric("blocked", "0")
        self._set_metric("total", "0")
        self._set_metric("rate", "0%")
        self.stats_rate_label.configure(text="0.0 ev/s")
        if self._active_page == "Stats":
            self._draw_traffic_chart()
        self.bottom_status.configure(text="Log cleared")

    def _export_csv(self) -> None:
        rows = [
            self.table.item(item, "values")
            for item in self.table.get_children("")
        ]
        if not rows:
            messagebox.showinfo("Nothing to export", "The traffic log is empty.", parent=self.root)
            return
        filename = f"waf_events_{datetime.now():%Y%m%d_%H%M%S}.csv"
        try:
            with open(filename, "w", newline="", encoding="utf-8") as fh:
                writer = csv.writer(fh)
                writer.writerow(
                    ["time", "action", "method", "path", "client", "status", "rule"]
                )
                writer.writerows(rows)
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc), parent=self.root)
            return
        self.bottom_status.configure(text=f"Exported {len(rows)} rows → {filename}")

    # ------------------------------------------------------------------ #
    # Context menu / detail
    # ------------------------------------------------------------------ #
    def _selected_item(self) -> str | None:
        sel = self.table.selection()
        return sel[0] if sel else None

    def _show_context_menu(self, event: tk.Event) -> None:
        item = self.table.identify_row(event.y)
        if not item:
            return
        self.table.selection_set(item)
        self._context_menu.tk_popup(event.x_root, event.y_root)

    def _copy_cell(self, column: str) -> None:
        item = self._selected_item()
        if not item:
            return
        value = self.table.set(item, column)
        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        self.bottom_status.configure(text=f"Copied {column}: {value}")

    def _copy_row(self) -> None:
        item = self._selected_item()
        if not item:
            return
        values = self.table.item(item, "values")
        text = " | ".join(str(v) for v in values)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.bottom_status.configure(text="Copied full row")

    def _show_detail(self, _event: tk.Event | None = None) -> None:
        item = self._selected_item()
        if not item:
            return
        values = self.table.item(item, "values")
        labels = ["Time", "Action", "Method", "Path", "Client", "Status", "Rule / Result"]
        lines = "\n".join(f"{lbl:12s}: {val}" for lbl, val in zip(labels, values))
        messagebox.showinfo("Event detail", lines, parent=self.root)

    # ------------------------------------------------------------------ #
    # Shutdown
    # ------------------------------------------------------------------ #
    def _close(self) -> None:
        if self._applications_refresh_id is not None:
            self.root.after_cancel(self._applications_refresh_id)
            self._applications_refresh_id = None
        try:
            self.application_registry.shutdown()
        except OSError as exc:
            messagebox.showerror(
                "Application shutdown warning",
                f"One or more listeners could not be shut down cleanly:\n{exc}",
                parent=self.root,
            )
        self._stop()
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    WAFDesktopApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()