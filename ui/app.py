"""Modern Windows Desktop GUI (Tkinter / ttk) for LAN IP Range & Port Scanner."""

from __future__ import annotations

import csv
import ctypes
import json
import os
import queue
import subprocess
import threading
import tkinter as tk
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from scanner import (
    PORT_PRESETS,
    HostScanResult,
    LanScannerEngine,
    NetworkInterface,
    ScanConfig,
    detect_network_interfaces,
    ip_to_int,
    parse_ip_range,
    parse_ports,
)

SPEED_PROFILES: dict[str, tuple[int, int, float]] = {
    "เร็วมาก (128 Threads / Ping 400ms)": (128, 400, 0.25),
    "สมดุล - แนะนำ (96 Threads / Ping 600ms)": (96, 600, 0.35),
    "ละเอียด / ข้ามวงแลน (64 Threads / Ping 1000ms)": (64, 1000, 0.55),
}


def _enable_windows_dpi_awareness() -> None:
    """Enable Per-Monitor / System DPI awareness on Windows for crisp Thai & English fonts."""
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


class LanScannerApp:
    """Main Desktop GUI Controller & Window."""

    COLUMNS = (
        "status",
        "ip",
        "hostname",
        "latency",
        "mac",
        "vendor",
        "device_type",
        "ports",
    )

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("LAN Network Scanner — ระบบสแกนเครื่องในวงแลน")

        # Scale geometry and row heights cleanly with Windows DPI
        dpi = self.root.winfo_fpixels("1i")
        self.scale = max(1.0, dpi / 96.0)
        win_w = min(int(1260 * max(1.0, self.scale * 0.88)), self.root.winfo_screenwidth() - 60)
        win_h = min(int(790 * max(1.0, self.scale * 0.88)), self.root.winfo_screenheight() - 80)
        pos_x = max(20, (self.root.winfo_screenwidth() - win_w) // 2)
        pos_y = max(20, (self.root.winfo_screenheight() - win_h) // 2)
        self.root.geometry(f"{win_w}x{win_h}+{pos_x}+{pos_y}")
        self.root.minsize(980, 640)
        self.root.configure(bg="#F1F5F9")

        self.engine = LanScannerEngine()
        self.event_queue: queue.Queue[tuple] = queue.Queue()
        self.interfaces: list[NetworkInterface] = []
        self.results_by_ip: dict[str, HostScanResult] = {}
        self.sort_col: str = "ip"
        self.sort_desc: bool = False
        self.last_elapsed_sec: float = 0.0

        # Tkinter Variables
        self.adapter_var = tk.StringVar()
        self.start_ip_var = tk.StringVar(value="192.168.1.1")
        self.end_ip_var = tk.StringVar(value="192.168.1.254")
        self.range_hint_var = tk.StringVar(value="เป้าหมาย: 254 IP")

        self.scan_ports_var = tk.BooleanVar(value=True)
        default_preset = next(iter(PORT_PRESETS.keys()))
        self.port_preset_var = tk.StringVar(value=default_preset)
        self.ports_text_var = tk.StringVar(value=PORT_PRESETS[default_preset])
        self.speed_var = tk.StringVar(value="สมดุล - แนะนำ (96 Threads / Ping 600ms)")

        self.only_online_var = tk.BooleanVar(value=True)
        self.search_var = tk.StringVar()

        self.stat_total_var = tk.StringVar(value="0")
        self.stat_online_var = tk.StringVar(value="0")
        self.stat_offline_var = tk.StringVar(value="0")
        self.stat_ports_var = tk.StringVar(value="0")
        self.stat_time_var = tk.StringVar(value="0.0 วินาที")

        self.status_text_var = tk.StringVar(value="พร้อมสแกน — เลือกการ์ดแลนหรือกำหนดช่วง IP แล้วกด 'เริ่มสแกน'")
        self.progress_var = tk.DoubleVar(value=0.0)
        self.detail_var = tk.StringVar(value="คลิกเลือกเครื่องในตารางเพื่อดูรายละเอียดเพิ่มเติม หรือคลิกขวาเพื่อเปิดเมนูคำสั่งด่วน")

        self._configure_styles()
        self._build_layout()
        self._bind_events()
        self.refresh_interfaces(initial=True)
        self.root.after(60, self._poll_queue)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")

        row_h = max(28, int(29 * self.scale))

        style.configure(".", font=("Segoe UI", 10), background="#F1F5F9", foreground="#0F172A")
        style.configure("Card.TFrame", background="#FFFFFF", relief="flat")
        style.configure("Surface.TFrame", background="#F1F5F9")

        style.configure(
            "FieldLabel.TLabel",
            background="#FFFFFF",
            foreground="#334155",
            font=("Segoe UI", 9, "bold"),
        )
        style.configure(
            "Hint.TLabel",
            background="#FFFFFF",
            foreground="#2563EB",
            font=("Segoe UI", 9, "bold"),
        )
        style.configure(
            "Muted.TLabel",
            background="#FFFFFF",
            foreground="#64748B",
            font=("Segoe UI", 9),
        )

        # Primary / Stop / Secondary Buttons
        style.configure(
            "Primary.TButton",
            background="#2563EB",
            foreground="#FFFFFF",
            borderwidth=0,
            focusthickness=0,
            padding=(16, 8),
            font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "Primary.TButton",
            background=[("active", "#1D4ED8"), ("disabled", "#94A3B8")],
            foreground=[("disabled", "#E2E8F0")],
        )

        style.configure(
            "Danger.TButton",
            background="#DC2626",
            foreground="#FFFFFF",
            borderwidth=0,
            focusthickness=0,
            padding=(14, 8),
            font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "Danger.TButton",
            background=[("active", "#B91C1C"), ("disabled", "#CBD5E1")],
            foreground=[("disabled", "#64748B")],
        )

        style.configure(
            "Soft.TButton",
            background="#E2E8F0",
            foreground="#1E293B",
            borderwidth=0,
            focusthickness=0,
            padding=(11, 6),
            font=("Segoe UI", 9, "bold"),
        )
        style.map(
            "Soft.TButton",
            background=[("active", "#CBD5E1"), ("disabled", "#F1F5F9")],
            foreground=[("disabled", "#94A3B8")],
        )

        style.configure("Card.TCheckbutton", background="#FFFFFF", foreground="#1E293B", font=("Segoe UI", 9))
        style.map("Card.TCheckbutton", background=[("active", "#FFFFFF")])

        style.configure("TEntry", fieldbackground="#F8FAFC", bordercolor="#CBD5E1", padding=(6, 5))
        style.configure("TCombobox", fieldbackground="#F8FAFC", bordercolor="#CBD5E1", padding=(6, 4))

        style.configure(
            "Scan.Horizontal.TProgressbar",
            troughcolor="#E2E8F0",
            background="#2563EB",
            bordercolor="#E2E8F0",
            lightcolor="#3B82F6",
            darkcolor="#1D4ED8",
            thickness=10,
        )

        # Treeview Table
        style.configure(
            "Scanner.Treeview",
            background="#FFFFFF",
            fieldbackground="#FFFFFF",
            foreground="#0F172A",
            rowheight=row_h,
            borderwidth=0,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Scanner.Treeview.Heading",
            background="#E2E8F0",
            foreground="#1E293B",
            relief="flat",
            padding=(8, 7),
            font=("Segoe UI", 9, "bold"),
        )
        style.map(
            "Scanner.Treeview.Heading",
            background=[("active", "#CBD5E1")],
        )
        style.map(
            "Scanner.Treeview",
            background=[("selected", "#DBEAFE")],
            foreground=[("selected", "#1E3A8A")],
        )

    def _build_layout(self) -> None:
        # 1. Top Dark Header Banner
        header = tk.Frame(self.root, bg="#0F172A", padx=18, pady=12)
        header.pack(fill="x")

        title_box = tk.Frame(header, bg="#0F172A")
        title_box.pack(side="left")
        tk.Label(
            title_box,
            text="ระบบสแกนเครื่องในวงแลน (LAN IP & Port Scanner)",
            bg="#0F172A",
            fg="#F8FAFC",
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w")
        tk.Label(
            title_box,
            text="กำหนดช่วง IP ได้อิสระ • ตรวจจับ ARP / ICMP Ping / Hostname / MAC Vendor / พอร์ตที่เปิด",
            bg="#0F172A",
            fg="#94A3B8",
            font=("Segoe UI", 9),
        ).pack(anchor="w")

        export_box = tk.Frame(header, bg="#0F172A")
        export_box.pack(side="right")
        self.btn_export_csv = ttk.Button(
            export_box, text="บันทึก CSV (Excel)", style="Soft.TButton", command=self.export_csv
        )
        self.btn_export_csv.pack(side="left", padx=(0, 8))
        self.btn_export_json = ttk.Button(
            export_box, text="บันทึก JSON", style="Soft.TButton", command=self.export_json
        )
        self.btn_export_json.pack(side="left")

        # Main Padded Container
        body = ttk.Frame(self.root, style="Surface.TFrame", padding=(14, 12, 14, 12))
        body.pack(fill="both", expand=True)

        # 2. Configuration Card
        cfg_outer = tk.Frame(body, bg="#CBD5E1", padx=1, pady=1)
        cfg_outer.pack(fill="x", pady=(0, 10))
        cfg_card = ttk.Frame(cfg_outer, style="Card.TFrame", padding=(14, 12))
        cfg_card.pack(fill="x")
        cfg_card.columnconfigure(1, weight=1)
        cfg_card.columnconfigure(3, weight=1)

        # Row 0: Network Interface Selector + Speed Profile
        ttk.Label(cfg_card, text="การ์ดเครือข่าย (Adapter):", style="FieldLabel.TLabel").grid(
            row=0, column=0, sticky="w", padx=(0, 8), pady=(0, 8)
        )
        adapter_frame = ttk.Frame(cfg_card, style="Card.TFrame")
        adapter_frame.grid(row=0, column=1, columnspan=2, sticky="ew", pady=(0, 8), padx=(0, 12))
        adapter_frame.columnconfigure(0, weight=1)

        self.cmb_adapter = ttk.Combobox(
            adapter_frame, textvariable=self.adapter_var, state="readonly"
        )
        self.cmb_adapter.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ttk.Button(
            adapter_frame,
            text="รีเฟรชวงแลน",
            style="Soft.TButton",
            command=lambda: self.refresh_interfaces(initial=False),
        ).grid(row=0, column=1)

        speed_frame = ttk.Frame(cfg_card, style="Card.TFrame")
        speed_frame.grid(row=0, column=3, columnspan=2, sticky="ew", pady=(0, 8))
        speed_frame.columnconfigure(1, weight=1)
        ttk.Label(speed_frame, text="ความเร็วสแกน:", style="FieldLabel.TLabel").grid(
            row=0, column=0, sticky="w", padx=(0, 8)
        )
        self.cmb_speed = ttk.Combobox(
            speed_frame,
            textvariable=self.speed_var,
            values=list(SPEED_PROFILES.keys()),
            state="readonly",
        )
        self.cmb_speed.grid(row=0, column=1, sticky="ew")

        # Row 1: IP Range Specification + Action Buttons
        ttk.Label(cfg_card, text="ช่วง IP (Start – End):", style="FieldLabel.TLabel").grid(
            row=1, column=0, sticky="w", padx=(0, 8), pady=(0, 8)
        )

        ip_box = ttk.Frame(cfg_card, style="Card.TFrame")
        ip_box.grid(row=1, column=1, columnspan=2, sticky="ew", pady=(0, 8), padx=(0, 12))
        self.ent_start_ip = ttk.Entry(ip_box, textvariable=self.start_ip_var, width=20, font=("Consolas", 10))
        self.ent_start_ip.pack(side="left")
        ttk.Label(ip_box, text="  ถึง  ", style="FieldLabel.TLabel").pack(side="left")
        self.ent_end_ip = ttk.Entry(ip_box, textvariable=self.end_ip_var, width=20, font=("Consolas", 10))
        self.ent_end_ip.pack(side="left")
        ttk.Button(
            ip_box,
            text="ทั้งวง /24 (.1-.254)",
            style="Soft.TButton",
            command=self._fill_full_24_range,
        ).pack(side="left", padx=(8, 8))
        ttk.Label(ip_box, textvariable=self.range_hint_var, style="Hint.TLabel").pack(side="left")

        action_box = ttk.Frame(cfg_card, style="Card.TFrame")
        action_box.grid(row=1, column=3, columnspan=2, sticky="e", pady=(0, 8))
        self.btn_start = ttk.Button(
            action_box, text="▶ เริ่มสแกน (Start Scan)", style="Primary.TButton", command=self.start_scan
        )
        self.btn_start.pack(side="left", padx=(0, 8))
        self.btn_stop = ttk.Button(
            action_box, text="■ หยุด", style="Danger.TButton", command=self.stop_scan, state="disabled"
        )
        self.btn_stop.pack(side="left")

        # Row 2: Port Scanning Controls
        self.chk_ports = ttk.Checkbutton(
            cfg_card,
            text="สแกนพอร์ตบริการ:",
            variable=self.scan_ports_var,
            style="Card.TCheckbutton",
            command=self._toggle_port_controls,
        )
        self.chk_ports.grid(row=2, column=0, sticky="w", padx=(0, 8))

        port_box = ttk.Frame(cfg_card, style="Card.TFrame")
        port_box.grid(row=2, column=1, columnspan=4, sticky="ew")
        port_box.columnconfigure(2, weight=1)

        self.cmb_port_preset = ttk.Combobox(
            port_box,
            textvariable=self.port_preset_var,
            values=[*PORT_PRESETS.keys(), "กำหนดพอร์ตเอง (Custom)"],
            state="readonly",
            width=28,
        )
        self.cmb_port_preset.grid(row=0, column=0, sticky="w", padx=(0, 8))

        ttk.Label(port_box, text="พอร์ต TCP:", style="Muted.TLabel").grid(
            row=0, column=1, sticky="w", padx=(0, 6)
        )
        self.ent_ports = ttk.Entry(port_box, textvariable=self.ports_text_var, font=("Consolas", 9))
        self.ent_ports.grid(row=0, column=2, sticky="ew")

        # 3. Summary Stat Cards Row
        stats_frame = ttk.Frame(body, style="Surface.TFrame")
        stats_frame.pack(fill="x", pady=(0, 10))
        for idx in range(5):
            stats_frame.columnconfigure(idx, weight=1)

        self._create_stat_card(stats_frame, 0, "เป้าหมายในช่วง IP", self.stat_total_var, "#0F172A")
        self._create_stat_card(stats_frame, 1, "ออนไลน์ (Online)", self.stat_online_var, "#059669")
        self._create_stat_card(stats_frame, 2, "ไม่ตอบสนอง (Offline)", self.stat_offline_var, "#64748B")
        self._create_stat_card(stats_frame, 3, "พบพอร์ตเปิดบริการ", self.stat_ports_var, "#2563EB")
        self._create_stat_card(stats_frame, 4, "เวลาที่ใช้สแกน", self.stat_time_var, "#7C3AED")

        # 4. Progress & Filter Bar
        filter_outer = tk.Frame(body, bg="#CBD5E1", padx=1, pady=1)
        filter_outer.pack(fill="x", pady=(0, 8))
        filter_bar = ttk.Frame(filter_outer, style="Card.TFrame", padding=(12, 8))
        filter_bar.pack(fill="x")

        left_prog = ttk.Frame(filter_bar, style="Card.TFrame")
        left_prog.pack(side="left", fill="x", expand=True, padx=(0, 16))
        ttk.Label(left_prog, textvariable=self.status_text_var, style="FieldLabel.TLabel").pack(
            anchor="w", pady=(0, 4)
        )
        self.progress_bar = ttk.Progressbar(
            left_prog,
            variable=self.progress_var,
            maximum=100.0,
            mode="determinate",
            style="Scan.Horizontal.TProgressbar",
        )
        self.progress_bar.pack(fill="x")

        right_filter = ttk.Frame(filter_bar, style="Card.TFrame")
        right_filter.pack(side="right")
        ttk.Checkbutton(
            right_filter,
            text="แสดงเฉพาะเครื่อง Online",
            variable=self.only_online_var,
            style="Card.TCheckbutton",
            command=self.refresh_table_view,
        ).pack(side="left", padx=(0, 14))

        ttk.Label(right_filter, text="ค้นหา:", style="FieldLabel.TLabel").pack(side="left", padx=(0, 6))
        self.ent_search = ttk.Entry(right_filter, textvariable=self.search_var, width=28)
        self.ent_search.pack(side="left", padx=(0, 6))
        ttk.Button(
            right_filter,
            text="ล้าง",
            style="Soft.TButton",
            command=lambda: self.search_var.set(""),
        ).pack(side="left")

        # 5. Results Table (Treeview)
        table_outer = tk.Frame(body, bg="#CBD5E1", padx=1, pady=1)
        table_outer.pack(fill="both", expand=True, pady=(0, 8))
        table_frame = ttk.Frame(table_outer, style="Card.TFrame")
        table_frame.pack(fill="both", expand=True)
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        self.tree = ttk.Treeview(
            table_frame,
            columns=self.COLUMNS,
            show="headings",
            style="Scanner.Treeview",
            selectmode="browse",
        )
        self.tree.grid(row=0, column=0, sticky="nsew")

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        vsb.grid(row=0, column=1, sticky="ns")
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        hsb.grid(row=1, column=0, sticky="ew")
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._headings_meta: dict[str, tuple[str, int, str]] = {
            "status": ("สถานะ", 95, "center"),
            "ip": ("IP Address", 130, "w"),
            "hostname": ("ชื่อเครื่อง (Hostname)", 200, "w"),
            "latency": ("Ping", 95, "center"),
            "mac": ("MAC Address", 145, "center"),
            "vendor": ("ยี่ห้ออุปกรณ์ (Vendor)", 190, "w"),
            "device_type": ("ประเภทอุปกรณ์", 150, "w"),
            "ports": ("พอร์ตที่เปิด (Open Ports)", 250, "w"),
        }
        for col_id, (label, width, anchor) in self._headings_meta.items():
            self.tree.heading(col_id, text=label, command=lambda c=col_id: self.sort_by_column(c))
            stretch = col_id in ("hostname", "vendor", "ports")
            self.tree.column(col_id, width=width, minwidth=75, anchor=anchor, stretch=stretch)

        # Row color tags
        self.tree.tag_configure("online_even", background="#FFFFFF", foreground="#0F172A")
        self.tree.tag_configure("online_odd", background="#F8FAFC", foreground="#0F172A")
        self.tree.tag_configure("local_pc", background="#ECFDF5", foreground="#065F46")
        self.tree.tag_configure("offline_row", background="#FAFAFA", foreground="#94A3B8")

        # 6. Bottom Inspector & Quick Action Strip
        bottom_outer = tk.Frame(body, bg="#CBD5E1", padx=1, pady=1)
        bottom_outer.pack(fill="x")
        bottom_bar = ttk.Frame(bottom_outer, style="Card.TFrame", padding=(12, 8))
        bottom_bar.pack(fill="x")

        ttk.Label(
            bottom_bar,
            textvariable=self.detail_var,
            style="Muted.TLabel",
        ).pack(side="left", fill="x", expand=True)

        quick_btns = ttk.Frame(bottom_bar, style="Card.TFrame")
        quick_btns.pack(side="right")
        ttk.Button(quick_btns, text="คัดลอก IP", style="Soft.TButton", command=self.copy_selected_ip).pack(
            side="left", padx=(0, 5)
        )
        ttk.Button(quick_btns, text="คัดลอก MAC", style="Soft.TButton", command=self.copy_selected_mac).pack(
            side="left", padx=(0, 5)
        )
        ttk.Button(quick_btns, text="เปิดเว็บ", style="Soft.TButton", command=self.open_selected_web).pack(
            side="left", padx=(0, 5)
        )
        ttk.Button(quick_btns, text="Remote RDP", style="Soft.TButton", command=self.open_selected_rdp).pack(
            side="left", padx=(0, 5)
        )
        ttk.Button(quick_btns, text="แชร์ไฟล์ \\\\IP", style="Soft.TButton", command=self.open_selected_smb).pack(
            side="left", padx=(0, 5)
        )
        ttk.Button(quick_btns, text="สแกนซ้ำจุดนี้", style="Soft.TButton", command=self.rescan_selected_host).pack(
            side="left"
        )

        # Right-click Context Menu
        self.ctx_menu = tk.Menu(self.root, tearoff=0, font=("Segoe UI", 9))
        self.ctx_menu.add_command(label="คัดลอก IP Address", command=self.copy_selected_ip)
        self.ctx_menu.add_command(label="คัดลอก MAC Address", command=self.copy_selected_mac)
        self.ctx_menu.add_command(label="คัดลอกข้อมูลทั้งแถว", command=self.copy_selected_row)
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="เปิดผ่านเว็บเบราว์เซอร์ (HTTP / HTTPS)", command=self.open_selected_web)
        self.ctx_menu.add_command(label="เชื่อมต่อ Remote Desktop (RDP)", command=self.open_selected_rdp)
        self.ctx_menu.add_command(label="เปิดโฟลเดอร์แชร์ (\\\\IP)", command=self.open_selected_smb)
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="สแกนเครื่องนี้ซ้ำอีกครั้ง", command=self.rescan_selected_host)

        self._update_heading_arrows()

    def _create_stat_card(
        self, parent: ttk.Frame, col: int, title: str, value_var: tk.StringVar, accent_hex: str
    ) -> None:
        padx = (0, 8) if col < 4 else (0, 0)
        border = tk.Frame(parent, bg="#CBD5E1", padx=1, pady=1)
        border.grid(row=0, column=col, sticky="ew", padx=padx)
        inner = tk.Frame(border, bg="#FFFFFF", padx=12, pady=8)
        inner.pack(fill="both", expand=True)

        tk.Label(
            inner, text=title, bg="#FFFFFF", fg="#64748B", font=("Segoe UI", 8, "bold")
        ).pack(anchor="w")
        tk.Label(
            inner, textvariable=value_var, bg="#FFFFFF", fg=accent_hex, font=("Segoe UI", 15, "bold")
        ).pack(anchor="w", pady=(2, 0))

    def _bind_events(self) -> None:
        self.cmb_adapter.bind("<<ComboboxSelected>>", self._on_adapter_selected)
        self.cmb_port_preset.bind("<<ComboboxSelected>>", self._on_port_preset_selected)
        self.ent_ports.bind("<KeyRelease>", self._on_ports_edited)

        self.start_ip_var.trace_add("write", lambda *_: self._update_range_preview())
        self.end_ip_var.trace_add("write", lambda *_: self._update_range_preview())
        self.search_var.trace_add("write", lambda *_: self.refresh_table_view())

        self.ent_start_ip.bind("<Return>", lambda _e: self.start_scan())
        self.ent_end_ip.bind("<Return>", lambda _e: self.start_scan())

        self.tree.bind("<<TreeviewSelect>>", self._on_row_selected)
        self.tree.bind("<Button-3>", self._on_right_click)
        self.tree.bind("<Double-1>", lambda _e: self.open_selected_web())

    def refresh_interfaces(self, initial: bool = False) -> None:
        self.interfaces = detect_network_interfaces()
        labels = [iface.display_label for iface in self.interfaces]
        labels.append("กำหนดช่วง IP เอง (Custom IP Range)")
        self.cmb_adapter["values"] = labels

        if self.interfaces:
            self.cmb_adapter.current(0)
            first = self.interfaces[0]
            self.start_ip_var.set(first.start_ip)
            self.end_ip_var.set(first.end_ip)
            if not initial:
                self.status_text_var.set(f"อัปเดตการ์ดแลนแล้ว ({len(self.interfaces)} รายการ) — เลือก {first.name}")
        else:
            self.cmb_adapter.current(0)
        self._update_range_preview()

    def _on_adapter_selected(self, _event: object = None) -> None:
        idx = self.cmb_adapter.current()
        if 0 <= idx < len(self.interfaces):
            iface = self.interfaces[idx]
            self.start_ip_var.set(iface.start_ip)
            self.end_ip_var.set(iface.end_ip)

    def _fill_full_24_range(self) -> None:
        raw = self.start_ip_var.get().strip().split("/")[0].split("-")[0].strip()
        parts = raw.split(".")
        if len(parts) >= 3 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts[:3]):
            base = ".".join(parts[:3])
            self.start_ip_var.set(f"{base}.1")
            self.end_ip_var.set(f"{base}.254")

    def _update_range_preview(self) -> None:
        try:
            ips = parse_ip_range(self.start_ip_var.get(), self.end_ip_var.get())
            self.range_hint_var.set(f"เป้าหมาย: {len(ips):,} IP")
        except Exception:
            self.range_hint_var.set("รูปแบบ IP ยังไม่สมบูรณ์")

    def _toggle_port_controls(self) -> None:
        enabled = self.scan_ports_var.get()
        self.cmb_port_preset.configure(state="readonly" if enabled else "disabled")
        self.ent_ports.configure(state="normal" if enabled else "disabled")

    def _on_port_preset_selected(self, _event: object = None) -> None:
        choice = self.port_preset_var.get()
        if choice in PORT_PRESETS:
            self.ports_text_var.set(PORT_PRESETS[choice])

    def _on_ports_edited(self, _event: object = None) -> None:
        current = self.ports_text_var.get().strip()
        for preset_name, preset_val in PORT_PRESETS.items():
            if current == preset_val:
                self.port_preset_var.set(preset_name)
                return
        self.port_preset_var.set("กำหนดพอร์ตเอง (Custom)")

    def _build_scan_config(self, override_ips: list[str] | None = None) -> ScanConfig | None:
        try:
            s_raw = self.start_ip_var.get().strip()
            e_raw = self.end_ip_var.get().strip()
            # If user pasted CIDR (e.g. 192.168.31.0/24) or single dash range in Start IP, normalize Start/End boxes cleanly
            if override_ips is None and ("," not in s_raw) and ("/" in s_raw or ("-" in s_raw and not e_raw)):
                from scanner.network_utils import expand_single_range_token

                exp_s, exp_e = expand_single_range_token(s_raw)
                self.start_ip_var.set(exp_s)
                self.end_ip_var.set(exp_e)
                s_raw, e_raw = exp_s, exp_e

            target_ips = override_ips if override_ips is not None else parse_ip_range(s_raw, e_raw)
        except Exception as exc:
            messagebox.showerror("ช่วง IP ไม่ถูกต้อง", str(exc), parent=self.root)
            return None

        if not target_ips:
            messagebox.showwarning("ไม่มีรายการ IP", "กรุณาระบุช่วง IP ที่ต้องการสแกน", parent=self.root)
            return None

        if len(target_ips) > 2048 and override_ips is None:
            confirm = messagebox.askyesno(
                "ยืนยันการสแกนช่วง IP ขนาดใหญ่",
                f"ช่วง IP ที่ระบุมีจำนวน {len(target_ips):,} รายการ อาจใช้เวลาสแกนหลายนาที\nต้องการดำเนินการสแกนต่อหรือไม่?",
                parent=self.root,
            )
            if not confirm:
                return None

        scan_ports = self.scan_ports_var.get()
        ports: list[int] = []
        if scan_ports:
            try:
                ports = parse_ports(self.ports_text_var.get())
            except Exception as exc:
                messagebox.showerror("รายการพอร์ตไม่ถูกต้อง", str(exc), parent=self.root)
                return None

        workers, ping_ms, port_sec = SPEED_PROFILES.get(
            self.speed_var.get(), (96, 600, 0.35)
        )
        return ScanConfig(
            target_ips=target_ips,
            scan_ports=scan_ports,
            ports=ports,
            ping_timeout_ms=ping_ms,
            port_timeout_sec=port_sec,
            max_workers=workers,
            resolve_hostname=True,
            local_interfaces=self.interfaces,
        )

    def start_scan(self) -> None:
        if self.engine.is_running:
            return
        config = self._build_scan_config()
        if config is None:
            return

        # Reset state & UI
        self.results_by_ip.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)

        total = len(config.target_ips)
        self.stat_total_var.set(f"{total:,}")
        self.stat_online_var.set("0")
        self.stat_offline_var.set("0")
        self.stat_ports_var.set("0")
        self.stat_time_var.set("กำลังสแกน...")
        self.progress_var.set(0.0)
        self.status_text_var.set(
            f"กำลังเริ่มสแกน {config.target_ips[0]} ถึง {config.target_ips[-1]} ({total:,} IP)..."
        )

        self._set_scanning_ui_state(True)

        worker = threading.Thread(
            target=self._scan_worker_thread, args=(config, False), daemon=True
        )
        worker.start()

    def stop_scan(self) -> None:
        if self.engine.is_running:
            self.status_text_var.set("กำลังหยุดการสแกน กรุณารอสักครู่...")
            self.engine.stop()

    def rescan_selected_host(self) -> None:
        if self.engine.is_running:
            return
        res = self._get_selected_result()
        if not res:
            messagebox.showinfo("เลือกเครื่องก่อน", "กรุณาคลิกเลือกแถวเครื่องในตารางที่ต้องการสแกนซ้ำ", parent=self.root)
            return
        config = self._build_scan_config(override_ips=[res.ip])
        if config is None:
            return
        self.status_text_var.set(f"กำลังสแกนซ้ำที่ {res.ip} ...")
        self._set_scanning_ui_state(True)
        worker = threading.Thread(
            target=self._scan_worker_thread, args=(config, True), daemon=True
        )
        worker.start()

    def _scan_worker_thread(self, config: ScanConfig, is_single_rescan: bool) -> None:
        def on_host_done(res: HostScanResult, done_count: int, total_count: int) -> None:
            self.event_queue.put(("host", res, done_count, total_count, is_single_rescan))

        def on_finished(cancelled: bool, elapsed: float) -> None:
            self.event_queue.put(("done", cancelled, elapsed, is_single_rescan))

        self.engine.run_scan(config, on_host_done=on_host_done, on_finished=on_finished)

    def _poll_queue(self) -> None:
        batch_updated = False
        processed = 0
        latest_progress: tuple[int, int] | None = None
        finished_payload: tuple[bool, float, bool] | None = None

        while processed < 60:
            try:
                msg = self.event_queue.get_nowait()
            except queue.Empty:
                break
            processed += 1
            kind = msg[0]
            if kind == "host":
                _, res, done_count, total_count, is_single_rescan = msg
                self.results_by_ip[res.ip] = res
                batch_updated = True
                if not is_single_rescan:
                    latest_progress = (done_count, total_count)
            elif kind == "done":
                _, cancelled, elapsed, is_single_rescan = msg
                finished_payload = (cancelled, elapsed, is_single_rescan)

        if latest_progress is not None:
            done_c, total_c = latest_progress
            pct = (done_c / total_c * 100.0) if total_c else 100.0
            self.progress_var.set(pct)
            self.status_text_var.set(f"กำลังสแกน... {done_c:,} / {total_c:,} IP ({pct:.0f}%)")

        if batch_updated:
            self._recalc_stats()
            self.refresh_table_view()

        if finished_payload is not None:
            cancelled, elapsed, is_single_rescan = finished_payload
            self._set_scanning_ui_state(False)
            self._recalc_stats()
            self.refresh_table_view()
            if not is_single_rescan:
                self.last_elapsed_sec = elapsed
                self.stat_time_var.set(f"{elapsed:.1f} วินาที")
                online_n = sum(1 for r in self.results_by_ip.values() if r.online)
                if cancelled:
                    self.status_text_var.set(
                        f"หยุดการสแกนแล้ว — พบเครื่องออนไลน์ {online_n:,} เครื่อง (ใช้เวลา {elapsed:.1f} วินาที)"
                    )
                else:
                    self.progress_var.set(100.0)
                    self.status_text_var.set(
                        f"สแกนเสร็จสมบูรณ์ — พบเครื่องออนไลน์ {online_n:,} จาก {len(self.results_by_ip):,} IP ({elapsed:.1f} วินาที)"
                    )
            else:
                self.status_text_var.set(f"อัปเดตสถานะเครื่องเรียบร้อย ({elapsed:.1f} วินาที)")
                self._on_row_selected()

        self.root.after(60, self._poll_queue)

    def _set_scanning_ui_state(self, scanning: bool) -> None:
        self.btn_start.configure(state="disabled" if scanning else "normal")
        self.btn_stop.configure(state="normal" if scanning else "disabled")
        self.ent_start_ip.configure(state="disabled" if scanning else "normal")
        self.ent_end_ip.configure(state="disabled" if scanning else "normal")
        self.cmb_adapter.configure(state="disabled" if scanning else "readonly")

    def _recalc_stats(self) -> None:
        all_res = list(self.results_by_ip.values())
        online_c = sum(1 for r in all_res if r.online)
        offline_c = sum(1 for r in all_res if not r.online)
        ports_c = sum(1 for r in all_res if r.online and r.open_ports)
        if all_res:
            self.stat_total_var.set(f"{max(int(self.stat_total_var.get().replace(',', '') or 0), len(all_res)):,}")
        self.stat_online_var.set(f"{online_c:,}")
        self.stat_offline_var.set(f"{offline_c:,}")
        self.stat_ports_var.set(f"{ports_c:,}")

    def _sort_key(self, res: HostScanResult) -> tuple:
        col = self.sort_col
        if col == "status":
            return (0 if res.online else 1, ip_to_int(res.ip))
        if col == "ip":
            return (ip_to_int(res.ip),)
        if col == "hostname":
            return (0 if res.hostname != "-" else 1, res.hostname.lower(), ip_to_int(res.ip))
        if col == "latency":
            val = res.latency_ms if (res.online and res.latency_ms is not None) else 999999
            return (val, ip_to_int(res.ip))
        if col == "mac":
            return (0 if res.mac != "-" else 1, res.mac, ip_to_int(res.ip))
        if col == "vendor":
            return (0 if res.vendor != "-" else 1, res.vendor.lower(), ip_to_int(res.ip))
        if col == "device_type":
            return (0 if res.online else 1, res.device_type.lower(), ip_to_int(res.ip))
        if col == "ports":
            return (-len(res.open_ports), res.open_ports, ip_to_int(res.ip))
        return (ip_to_int(res.ip),)

    def sort_by_column(self, col_id: str) -> None:
        if self.sort_col == col_id:
            self.sort_desc = not self.sort_desc
        else:
            self.sort_col = col_id
            self.sort_desc = False
        self._update_heading_arrows()
        self.refresh_table_view()

    def _update_heading_arrows(self) -> None:
        for col_id, (base_label, _, _) in self._headings_meta.items():
            if col_id == self.sort_col:
                arrow = " ▼" if self.sort_desc else " ▲"
                self.tree.heading(col_id, text=f"{base_label}{arrow}")
            else:
                self.tree.heading(col_id, text=base_label)

    def refresh_table_view(self) -> None:
        selected_ips = self.tree.selection()
        prev_sel = selected_ips[0] if selected_ips else None

        only_online = self.only_online_var.get()
        q = self.search_var.get().strip().lower()

        filtered: list[HostScanResult] = []
        for res in self.results_by_ip.values():
            if only_online and not res.online:
                continue
            if q:
                haystack = " ".join(
                    [
                        res.ip,
                        res.hostname,
                        res.workgroup,
                        res.mac,
                        res.vendor,
                        res.device_type,
                        res.ports_display,
                    ]
                ).lower()
                if q not in haystack:
                    continue
            filtered.append(res)

        filtered.sort(key=self._sort_key, reverse=self.sort_desc)

        self.tree.delete(*self.tree.get_children())
        for idx, res in enumerate(filtered):
            status_str = "● Online" if res.online else "○ Offline"
            if not res.online:
                tag = "offline_row"
            elif res.device_type.startswith("เครื่องนี้"):
                tag = "local_pc"
            else:
                tag = "online_even" if idx % 2 == 0 else "online_odd"

            self.tree.insert(
                "",
                "end",
                iid=res.ip,
                values=(
                    status_str,
                    res.ip,
                    res.hostname,
                    res.latency_text,
                    res.mac,
                    res.vendor,
                    res.device_type,
                    res.ports_display,
                ),
                tags=(tag,),
            )

        if prev_sel and self.tree.exists(prev_sel):
            self.tree.selection_set(prev_sel)

    def _get_selected_result(self) -> HostScanResult | None:
        sel = self.tree.selection()
        if not sel:
            return None
        return self.results_by_ip.get(sel[0])

    def _on_row_selected(self, _event: object = None) -> None:
        res = self._get_selected_result()
        if not res:
            return
        wg_str = f" | Workgroup: {res.workgroup}" if res.workgroup else ""
        ttl_str = f" | TTL: {res.ttl}" if res.ttl is not None else ""
        method_str = f" | ตรวจพบด้วย: {res.discovery_method}" if res.discovery_method != "-" else ""
        self.detail_var.set(
            f"IP: {res.ip}  •  ชื่อเครื่อง: {res.hostname}{wg_str}  •  MAC: {res.mac} ({res.vendor})"
            f"{method_str}{ttl_str}  •  พอร์ต: {res.ports_display}"
        )

    def _on_right_click(self, event: tk.Event) -> None:
        row_id = self.tree.identify_row(event.y)
        if row_id:
            self.tree.selection_set(row_id)
            self._on_row_selected()
            self.ctx_menu.tk_popup(event.x_root, event.y_root)

    def _copy_to_clipboard(self, text: str, label: str) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status_text_var.set(f"คัดลอก {label} ({text}) ไปยังคลิปบอร์ดแล้ว")

    def copy_selected_ip(self) -> None:
        res = self._get_selected_result()
        if res:
            self._copy_to_clipboard(res.ip, "IP Address")

    def copy_selected_mac(self) -> None:
        res = self._get_selected_result()
        if res and res.mac != "-":
            self._copy_to_clipboard(res.mac, "MAC Address")

    def copy_selected_row(self) -> None:
        res = self._get_selected_result()
        if res:
            line = (
                f"IP: {res.ip} | Status: {'Online' if res.online else 'Offline'} | "
                f"Hostname: {res.hostname} | Ping: {res.latency_text} | "
                f"MAC: {res.mac} | Vendor: {res.vendor} | Ports: {res.ports_display}"
            )
            self._copy_to_clipboard(line, "ข้อมูลเครื่อง")

    def open_selected_web(self) -> None:
        res = self._get_selected_result()
        if not res:
            return
        ports = set(res.open_ports)
        if 443 in ports:
            url = f"https://{res.ip}"
        elif 8443 in ports:
            url = f"https://{res.ip}:8443"
        elif 8080 in ports:
            url = f"http://{res.ip}:8080"
        elif 8000 in ports:
            url = f"http://{res.ip}:8000"
        elif 5000 in ports:
            url = f"http://{res.ip}:5000"
        else:
            url = f"http://{res.ip}"
        webbrowser.open(url)

    def open_selected_rdp(self) -> None:
        res = self._get_selected_result()
        if not res:
            return
        subprocess.Popen(["mstsc", f"/v:{res.ip}"])

    def open_selected_smb(self) -> None:
        res = self._get_selected_result()
        if not res:
            return
        try:
            os.startfile(f"\\\\{res.ip}")
        except OSError as exc:
            messagebox.showwarning("ไม่สามารถเปิดโฟลเดอร์แชร์", str(exc), parent=self.root)

    def _get_export_rows(self) -> list[HostScanResult]:
        if not self.results_by_ip:
            messagebox.showinfo("ยังไม่มีข้อมูล", "กรุณาสแกนเครือข่ายก่อนส่งออกข้อมูล", parent=self.root)
            return []
        only_online = self.only_online_var.get()
        rows = [r for r in self.results_by_ip.values() if (r.online or not only_online)]
        rows.sort(key=lambda r: ip_to_int(r.ip))
        return rows

    def export_csv(self) -> None:
        rows = self._get_export_rows()
        if not rows:
            return
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="บันทึกผลการสแกนเป็นไฟล์ CSV",
            defaultextension=".csv",
            initialfile=f"lan_scan_{stamp}.csv",
            filetypes=[("CSV Files (Excel UTF-8)", "*.csv"), ("All Files", "*.*")],
        )
        if not path:
            return
        try:
            # utf-8-sig ensures Microsoft Excel opens Thai text cleanly without garbled encoding
            with Path(path).open("w", encoding="utf-8-sig", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(
                    [
                        "สถานะ",
                        "IP Address",
                        "Hostname",
                        "Workgroup",
                        "Ping",
                        "MAC Address",
                        "Vendor",
                        "ประเภทอุปกรณ์",
                        "Open Ports",
                        "วิธีตรวจพบ",
                        "TTL",
                    ]
                )
                for r in rows:
                    writer.writerow(
                        [
                            "Online" if r.online else "Offline",
                            r.ip,
                            r.hostname,
                            r.workgroup,
                            r.latency_text,
                            r.mac,
                            r.vendor,
                            r.device_type,
                            r.ports_display,
                            r.discovery_method,
                            r.ttl if r.ttl is not None else "",
                        ]
                    )
            self.status_text_var.set(f"บันทึกไฟล์ CSV เรียบร้อย: {path}")
        except OSError as exc:
            messagebox.showerror("บันทึกไฟล์ไม่สำเร็จ", str(exc), parent=self.root)

    def export_json(self) -> None:
        rows = self._get_export_rows()
        if not rows:
            return
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="บันทึกผลการสแกนเป็นไฟล์ JSON",
            defaultextension=".json",
            initialfile=f"lan_scan_{stamp}.json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
        )
        if not path:
            return
        payload = {
            "exported_at": datetime.now().isoformat(timespec="seconds"),
            "total_records": len(rows),
            "online_count": sum(1 for r in rows if r.online),
            "devices": [
                {
                    "ip": r.ip,
                    "online": r.online,
                    "hostname": r.hostname,
                    "workgroup": r.workgroup,
                    "latency_ms": r.latency_ms,
                    "latency_text": r.latency_text,
                    "mac": r.mac,
                    "vendor": r.vendor,
                    "device_type": r.device_type,
                    "open_ports": r.open_ports,
                    "ports_display": r.ports_display,
                    "discovery_method": r.discovery_method,
                    "ttl": r.ttl,
                }
                for r in rows
            ],
        }
        try:
            Path(path).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            self.status_text_var.set(f"บันทึกไฟล์ JSON เรียบร้อย: {path}")
        except OSError as exc:
            messagebox.showerror("บันทึกไฟล์ไม่สำเร็จ", str(exc), parent=self.root)

    def _on_close(self) -> None:
        if self.engine.is_running:
            self.engine.stop()
        self.root.destroy()


def launch_app() -> None:
    """Initialize DPI awareness and start the Tkinter mainloop."""
    _enable_windows_dpi_awareness()
    root = tk.Tk()
    LanScannerApp(root)
    root.mainloop()
