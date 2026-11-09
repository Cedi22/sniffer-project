"""
ARP Sniffer & Spoofing Detector GUI
-----------------------------------
A graphical interface for real-time ARP packet inspection,
ARP cache poisoning detection, and security simulation.
"""

import sys
import os
import time
import queue
import random
import threading
import json
import base64
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# Add current folder to sys.path to ensure local imports succeed
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

try:
    from scapy.all import sniff, ARP, Ether, conf, sendp
except Exception as exc:
    messagebox.showerror(
        "Scapy Import Error",
        f"Failed to import Scapy: {exc}\nEnsure Npcap is installed and scapy is in your environment."
    )
    sys.exit(1)

from arp_detector import arp_cache, process_arp_packet
from simulate_spoof import send_spoof_packet
from cli_detector import AnomalySnifferCLI


class ArpSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ARP Sniffer & Anomaly Detector")
        self.root.geometry("1060x720")
        self.root.minsize(920, 600)

        # Sniffing state
        self.is_sniffing = False
        self.sniff_thread = None
        self.msg_queue = queue.Queue()

        # Statistics
        self.total_packets = 0
        self.arp_packets = 0
        self.alert_count = 0

        # Detailed host tracking: ip -> {mac, first_seen, last_seen, count, status}
        self.hosts = {}
        self.alerts = []

        # Phase 1 Anomaly Detection Engine
        self.engine = AnomalySnifferCLI(
            scan_threshold=20,
            scan_window=5.0,
            on_alert=lambda alert_type, data: self.msg_queue.put((alert_type, data)),
            on_cred=lambda cred_data: self.msg_queue.put(("CREDENTIAL", cred_data)),
            on_learn=lambda learn_data: self.msg_queue.put(("ARP_UPDATE", learn_data))
        )

        # Available network interfaces
        self.interfaces = self.load_interfaces()

        # Setup custom modern theme
        self.setup_theme()

        # Build UI layout
        self.build_ui()

        # Start periodic queue processor
        self.root.after(100, self.process_queue)
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def load_interfaces(self):
        """Fetch human-friendly interfaces from Scapy conf.ifaces."""
        iface_map = {}
        try:
            for iface_key, iface_obj in conf.ifaces.items():
                desc = getattr(iface_obj, "description", None) or getattr(iface_obj, "name", iface_key)
                display_label = f"{desc} ({getattr(iface_obj, 'ip', 'No IP')})"
                iface_map[display_label] = iface_key
        except Exception as e:
            iface_map[f"Default ({conf.iface})"] = conf.iface

        if not iface_map:
            iface_map["Default"] = conf.iface
        return iface_map

    def setup_theme(self):
        self.style = ttk.Style()
        try:
            self.style.theme_use("clam")
        except Exception:
            pass

        # Color palette
        self.colors = {
            "bg": "#1e222b",
            "card_bg": "#282c37",
            "card_border": "#3b4252",
            "fg": "#e5e9f0",
            "accent": "#4c78dd",
            "success": "#2e7d32",
            "danger": "#c62828",
            "warning": "#f57c00",
            "highlight": "#88c0d0"
        }

        self.root.configure(bg=self.colors["bg"])

        self.style.configure(".", background=self.colors["bg"], foreground=self.colors["fg"], font=("Segoe UI", 9))
        self.style.configure("TFrame", background=self.colors["bg"])
        self.style.configure("Card.TFrame", background=self.colors["card_bg"], relief="flat")
        self.style.configure("TLabel", background=self.colors["bg"], foreground=self.colors["fg"], font=("Segoe UI", 9))
        self.style.configure("Card.TLabel", background=self.colors["card_bg"], foreground=self.colors["fg"])

        # Buttons
        self.style.configure("Primary.TButton", font=("Segoe UI", 9, "bold"), padding=6)
        self.style.configure("Start.TButton", font=("Segoe UI", 9, "bold"), padding=6, background="#2e7d32", foreground="#ffffff")
        self.style.configure("Stop.TButton", font=("Segoe UI", 9, "bold"), padding=6, background="#c62828", foreground="#ffffff")
        self.style.configure("Action.TButton", font=("Segoe UI", 9), padding=5)

        # Notebook tabs
        self.style.configure("TNotebook", background=self.colors["bg"], tabmargins=[2, 5, 2, 0])
        self.style.configure("TNotebook.Tab", background="#2b303c", foreground=self.colors["fg"], padding=[12, 6], font=("Segoe UI", 9, "bold"))
        self.style.map("TNotebook.Tab", background=[("selected", self.colors["accent"])], foreground=[("selected", "#ffffff")])

        # Treeview
        self.style.configure("Treeview",
            background="#252932",
            foreground="#eceff4",
            fieldbackground="#252932",
            rowheight=26,
            font=("Segoe UI", 9)
        )
        self.style.configure("Treeview.Heading",
            background="#333846",
            foreground="#eceff4",
            font=("Segoe UI", 9, "bold"),
            relief="flat"
        )
        self.style.map("Treeview.Heading", background=[("active", "#3f4657")])
        self.style.map("Treeview", background=[("selected", "#3b5998")])

    def build_ui(self):
        # 1. Top Header Banner
        header = tk.Frame(self.root, bg="#14171d", padx=15, pady=10)
        header.pack(fill=tk.X)

        title_box = tk.Frame(header, bg="#14171d")
        title_box.pack(side=tk.LEFT)

        title_lbl = tk.Label(
            title_box,
            text="🛡️ ARP Sniffer & Spoofing Detector",
            font=("Segoe UI", 14, "bold"),
            bg="#14171d",
            fg="#61afef"
        )
        title_lbl.pack(anchor=tk.W)

        sub_lbl = tk.Label(
            title_box,
            text="Real-time ARP packet inspection, cache poisoning anomaly detection & penetration testing lab",
            font=("Segoe UI", 8),
            bg="#14171d",
            fg="#abb2bf"
        )
        sub_lbl.pack(anchor=tk.W)

        # Status badge
        self.status_badge = tk.Label(
            header,
            text="● STATUS: IDLE",
            font=("Segoe UI", 9, "bold"),
            bg="#3b4252",
            fg="#eceff4",
            padx=12,
            pady=4,
            relief="flat"
        )
        self.status_badge.pack(side=tk.RIGHT, pady=5)

        # 2. Metric / Stat Cards
        stats_frame = tk.Frame(self.root, bg=self.colors["bg"], padx=15, pady=8)
        stats_frame.pack(fill=tk.X)

        self.stat_cards = {}
        stat_configs = [
            ("total", "Total Packets", "0", "#61afef"),
            ("arp", "ARP Packets", "0", "#98c379"),
            ("hosts", "Cached Devices", "0", "#e5c07b"),
            ("alerts", "Spoof Alerts", "0", "#e06c75")
        ]

        for key, title, init_val, col in stat_configs:
            card = tk.Frame(stats_frame, bg=self.colors["card_bg"], padx=12, pady=6, relief="ridge", bd=1)
            card.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=4)

            t_lbl = tk.Label(card, text=title.upper(), font=("Segoe UI", 7, "bold"), bg=self.colors["card_bg"], fg="#808b96")
            t_lbl.pack(anchor=tk.W)

            v_lbl = tk.Label(card, text=init_val, font=("Segoe UI", 16, "bold"), bg=self.colors["card_bg"], fg=col)
            v_lbl.pack(anchor=tk.W)
            self.stat_cards[key] = v_lbl

        # 3. Controls Ribbon
        ctrl_frame = tk.Frame(self.root, bg=self.colors["card_bg"], padx=15, pady=8, relief="ridge", bd=1)
        ctrl_frame.pack(fill=tk.X, padx=15, pady=4)

        # Interface row
        lbl_iface = tk.Label(ctrl_frame, text="Interface:", font=("Segoe UI", 9, "bold"), bg=self.colors["card_bg"], fg=self.colors["fg"])
        lbl_iface.grid(row=0, column=0, sticky=tk.W, padx=(0, 6), pady=4)

        iface_keys = list(self.interfaces.keys())
        self.iface_var = tk.StringVar(value=iface_keys[0] if iface_keys else "")
        # Try to select the default one if present
        for label, dev in self.interfaces.items():
            if str(conf.iface) in str(dev) or "Wi-Fi" in label or "Ethernet" in label:
                self.iface_var.set(label)
                break

        self.iface_combo = ttk.Combobox(ctrl_frame, textvariable=self.iface_var, values=iface_keys, width=38, state="readonly")
        self.iface_combo.grid(row=0, column=1, sticky=tk.W, padx=4, pady=4)

        # Filter row
        lbl_filter = tk.Label(ctrl_frame, text="BPF Filter:", font=("Segoe UI", 9, "bold"), bg=self.colors["card_bg"], fg=self.colors["fg"])
        lbl_filter.grid(row=0, column=2, sticky=tk.W, padx=(12, 6), pady=4)

        self.filter_var = tk.StringVar(value="arp")
        self.filter_entry = ttk.Entry(ctrl_frame, textvariable=self.filter_var, width=14)
        self.filter_entry.grid(row=0, column=3, sticky=tk.W, padx=4, pady=4)

        # Action Buttons
        btn_frame = tk.Frame(ctrl_frame, bg=self.colors["card_bg"])
        btn_frame.grid(row=0, column=4, sticky=tk.E, padx=(15, 0), pady=4)
        ctrl_frame.columnconfigure(4, weight=1)

        self.btn_start = tk.Button(
            btn_frame,
            text="▶ Start Sniffer",
            command=self.start_sniffing,
            bg="#2e7d32",
            fg="white",
            activebackground="#1b5e20",
            activeforeground="white",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=10,
            pady=4,
            cursor="hand2"
        )
        self.btn_start.pack(side=tk.LEFT, padx=3)

        self.btn_stop = tk.Button(
            btn_frame,
            text="⏹ Stop",
            command=self.stop_sniffing,
            bg="#c62828",
            fg="white",
            activebackground="#b71c1c",
            activeforeground="white",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=10,
            pady=4,
            state=tk.DISABLED,
            cursor="hand2"
        )
        self.btn_stop.pack(side=tk.LEFT, padx=3)

        self.btn_clear = tk.Button(
            btn_frame,
            text="🧹 Clear",
            command=self.clear_all,
            bg="#3b4252",
            fg="white",
            activebackground="#4c566a",
            activeforeground="white",
            font=("Segoe UI", 9),
            relief="flat",
            padx=8,
            pady=4,
            cursor="hand2"
        )
        self.btn_clear.pack(side=tk.LEFT, padx=3)

        self.btn_export = tk.Button(
            btn_frame,
            text="💾 Export Report",
            command=self.export_report,
            bg="#4c78dd",
            fg="white",
            activebackground="#3b5eb2",
            activeforeground="white",
            font=("Segoe UI", 9),
            relief="flat",
            padx=8,
            pady=4,
            cursor="hand2"
        )
        self.btn_export.pack(side=tk.LEFT, padx=3)

        # 4. Main Notebook (Tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=15, pady=8)

        # Tab 1: ARP Table
        self.tab_arp = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_arp, text="  🌐 ARP Table & Devices  ")
        self.build_arp_tab()

        # Tab 2: Security Alerts
        self.tab_alerts = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_alerts, text="  🚨 Security Alerts  ")
        self.build_alerts_tab()

        # Tab 3: Live Packet Stream
        self.tab_packets = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_packets, text="  📡 Packet Stream  ")
        self.build_packets_tab()

        # Tab 4: Attack Simulation Lab
        self.tab_sim = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_sim, text="  🧪 Simulation & Verification Lab  ")
        self.build_simulation_tab()

        # 5. Bottom Status Strip
        bottom_strip = tk.Frame(self.root, bg="#14171d", padx=15, pady=4)
        bottom_strip.pack(fill=tk.X, side=tk.BOTTOM)

        self.lbl_footer = tk.Label(
            bottom_strip,
            text="Ready. Click 'Start Sniffer' to monitor network traffic or run simulations in the Lab tab.",
            font=("Segoe UI", 8),
            bg="#14171d",
            fg="#808b96"
        )
        self.lbl_footer.pack(side=tk.LEFT)

        lbl_engine = tk.Label(
            bottom_strip,
            text="Scapy Engine 2.8.0 | Python 3.10",
            font=("Segoe UI", 8),
            bg="#14171d",
            fg="#5c6370"
        )
        lbl_engine.pack(side=tk.RIGHT)

    def build_arp_tab(self):
        # Toolbar above ARP tree
        bar = tk.Frame(self.tab_arp, bg=self.colors["bg"], pady=4)
        bar.pack(fill=tk.X)

        tk.Label(bar, text="Search Host:").pack(side=tk.LEFT, padx=(0, 5))
        self.arp_search_var = tk.StringVar()
        self.arp_search_var.trace_add("write", lambda *args: self.refresh_arp_tree())
        search_entry = ttk.Entry(bar, textvariable=self.arp_search_var, width=22)
        search_entry.pack(side=tk.LEFT, padx=4)

        btn_flush = tk.Button(
            bar,
            text="Flush ARP Cache",
            command=self.flush_arp_cache,
            bg="#3b4252",
            fg="white",
            relief="flat",
            font=("Segoe UI", 8),
            padx=6,
            pady=2,
            cursor="hand2"
        )
        btn_flush.pack(side=tk.RIGHT, padx=4)

        # Treeview for hosts
        cols = ("ip", "mac", "count", "first_seen", "last_seen", "status")
        self.arp_tree = ttk.Treeview(self.tab_arp, columns=cols, show="headings", selectmode="browse")

        self.arp_tree.heading("ip", text="IP Address")
        self.arp_tree.heading("mac", text="MAC Address (Physical)")
        self.arp_tree.heading("count", text="Packets")
        self.arp_tree.heading("first_seen", text="First Seen")
        self.arp_tree.heading("last_seen", text="Last Seen")
        self.arp_tree.heading("status", text="Security Status")

        self.arp_tree.column("ip", width=140, anchor=tk.W)
        self.arp_tree.column("mac", width=170, anchor=tk.W)
        self.arp_tree.column("count", width=70, anchor=tk.CENTER)
        self.arp_tree.column("first_seen", width=110, anchor=tk.CENTER)
        self.arp_tree.column("last_seen", width=110, anchor=tk.CENTER)
        self.arp_tree.column("status", width=160, anchor=tk.W)

        self.arp_tree.tag_configure("normal", foreground="#98c379")
        self.arp_tree.tag_configure("conflict", foreground="#e06c75", background="#3d2327")

        scrollbar = ttk.Scrollbar(self.tab_arp, orient=tk.VERTICAL, command=self.arp_tree.yview)
        self.arp_tree.configure(yscrollcommand=scrollbar.set)

        self.arp_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def build_alerts_tab(self):
        # Alerts layout: Top table, bottom detail box
        container = tk.Frame(self.tab_alerts, bg=self.colors["bg"])
        container.pack(fill=tk.BOTH, expand=True, pady=4)

        # Alert table
        cols = ("time", "ip", "original_mac", "attacker_mac", "severity")
        self.alert_tree = ttk.Treeview(container, columns=cols, show="headings", height=8, selectmode="browse")

        self.alert_tree.heading("time", text="Time")
        self.alert_tree.heading("ip", text="Target IP")
        self.alert_tree.heading("original_mac", text="Baseline / Original MAC")
        self.alert_tree.heading("attacker_mac", text="Rogue Attacker MAC")
        self.alert_tree.heading("severity", text="Risk Level")

        self.alert_tree.column("time", width=90, anchor=tk.CENTER)
        self.alert_tree.column("ip", width=140, anchor=tk.W)
        self.alert_tree.column("original_mac", width=170, anchor=tk.W)
        self.alert_tree.column("attacker_mac", width=170, anchor=tk.W)
        self.alert_tree.column("severity", width=110, anchor=tk.CENTER)

        self.alert_tree.tag_configure("critical", foreground="#ffffff", background="#8a1c14")

        scrollbar = ttk.Scrollbar(container, orient=tk.VERTICAL, command=self.alert_tree.yview)
        self.alert_tree.configure(yscrollcommand=scrollbar.set)

        self.alert_tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.alert_tree.bind("<<TreeviewSelect>>", self.on_alert_selected)

        # Bottom detail pane
        detail_frame = tk.LabelFrame(
            self.tab_alerts,
            text="Threat Analysis & Incident Response Recommendations",
            bg=self.colors["card_bg"],
            fg="#e5c07b",
            font=("Segoe UI", 9, "bold"),
            padx=10,
            pady=8
        )
        detail_frame.pack(fill=tk.X, pady=6)

        self.alert_detail_text = tk.Text(
            detail_frame,
            height=6,
            bg="#1e222b",
            fg="#eceff4",
            font=("Consolas", 9),
            relief="flat",
            wrap=tk.WORD
        )
        self.alert_detail_text.pack(fill=tk.BOTH, expand=True)
        self.alert_detail_text.insert(
            tk.END,
            "No active security alerts. The detector will flag and dissect any ARP spoofing attempts here."
        )

    def build_packets_tab(self):
        bar = tk.Frame(self.tab_packets, bg=self.colors["bg"], pady=4)
        bar.pack(fill=tk.X)

        self.autoscroll_var = tk.BooleanVar(value=True)
        chk = tk.Checkbutton(
            bar,
            text="Auto-scroll to latest",
            variable=self.autoscroll_var,
            bg=self.colors["bg"],
            fg=self.colors["fg"],
            selectcolor="#252932",
            activebackground=self.colors["bg"],
            activeforeground=self.colors["fg"],
            font=("Segoe UI", 8)
        )
        chk.pack(side=tk.LEFT)

        btn_clear_log = tk.Button(
            bar,
            text="Clear Stream",
            command=self.clear_packet_stream,
            bg="#3b4252",
            fg="white",
            relief="flat",
            font=("Segoe UI", 8),
            padx=6,
            pady=2,
            cursor="hand2"
        )
        btn_clear_log.pack(side=tk.RIGHT)

        self.packet_text = tk.Text(
            self.tab_packets,
            bg="#181a1f",
            fg="#abb2bf",
            font=("Consolas", 9),
            relief="flat",
            wrap=tk.NONE
        )
        scrollbar_y = ttk.Scrollbar(self.tab_packets, orient=tk.VERTICAL, command=self.packet_text.yview)
        scrollbar_x = ttk.Scrollbar(self.tab_packets, orient=tk.HORIZONTAL, command=self.packet_text.xview)
        self.packet_text.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)

        self.packet_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)

        # Text tags for coloring
        self.packet_text.tag_configure("ALERT", foreground="#e06c75", font=("Consolas", 9, "bold"))
        self.packet_text.tag_configure("ARP", foreground="#98c379")
        self.packet_text.tag_configure("SYSTEM", foreground="#61afef")

    def build_simulation_tab(self):
        # Two panels: Left = Live packet injection, Right = Safe In-Memory validation
        container = tk.Frame(self.tab_sim, bg=self.colors["bg"], padx=10, pady=10)
        container.pack(fill=tk.BOTH, expand=True)

        # Panel 1: Live Injection
        p1 = tk.LabelFrame(
            container,
            text="1. Inject Rogue ARP Frame (Live Network Attack Simulation)",
            bg=self.colors["card_bg"],
            fg="#61afef",
            font=("Segoe UI", 9, "bold"),
            padx=12,
            pady=10
        )
        p1.pack(fill=tk.X, pady=(0, 10))

        desc1 = tk.Label(
            p1,
            text="Sends an unsolicited ARP Reply (Ethernet frame op=2) to claim that Target IP is mapped to a rogue MAC.\nRequires Npcap / Administrator privileges.",
            font=("Segoe UI", 8),
            justify=tk.LEFT,
            bg=self.colors["card_bg"],
            fg="#abb2bf"
        )
        desc1.grid(row=0, column=0, columnspan=4, sticky=tk.W, pady=(0, 8))

        # Target IP
        tk.Label(p1, text="Target IP:", bg=self.colors["card_bg"]).grid(row=1, column=0, sticky=tk.W, pady=4)
        self.sim_ip_var = tk.StringVar(value="192.168.1.1")
        entry_ip = ttk.Entry(p1, textvariable=self.sim_ip_var, width=18)
        entry_ip.grid(row=1, column=1, sticky=tk.W, padx=6, pady=4)

        btn_use_cached = tk.Button(
            p1,
            text="Select from Cache",
            command=self.select_cached_ip_for_sim,
            bg="#3b4252",
            fg="white",
            relief="flat",
            font=("Segoe UI", 8),
            padx=6,
            pady=2,
            cursor="hand2"
        )
        btn_use_cached.grid(row=1, column=2, sticky=tk.W, padx=4)

        # Fake MAC
        tk.Label(p1, text="Rogue Attacker MAC:", bg=self.colors["card_bg"]).grid(row=2, column=0, sticky=tk.W, pady=4)
        self.sim_mac_var = tk.StringVar(value="aa:bb:cc:11:22:33")
        entry_mac = ttk.Entry(p1, textvariable=self.sim_mac_var, width=18)
        entry_mac.grid(row=2, column=1, sticky=tk.W, padx=6, pady=4)

        btn_rand_mac = tk.Button(
            p1,
            text="Randomize MAC",
            command=self.generate_random_mac,
            bg="#3b4252",
            fg="white",
            relief="flat",
            font=("Segoe UI", 8),
            padx=6,
            pady=2,
            cursor="hand2"
        )
        btn_rand_mac.grid(row=2, column=2, sticky=tk.W, padx=4)

        # Inject Button
        btn_inject = tk.Button(
            p1,
            text="🚀 Inject Spoofed Packet",
            command=self.execute_sim_injection,
            bg="#e06c75",
            fg="white",
            activebackground="#be5046",
            activeforeground="white",
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padx=12,
            pady=5,
            cursor="hand2"
        )
        btn_inject.grid(row=3, column=0, columnspan=3, sticky=tk.W, pady=(8, 4))

        # Panel 2: Safe In-Memory Test Suite
        p2 = tk.LabelFrame(
            container,
            text="2. Safe In-Memory Lab Tests (Self-Contained / All Phase 1 Detectors)",
            bg=self.colors["card_bg"],
            fg="#98c379",
            font=("Segoe UI", 9, "bold"),
            padx=12,
            pady=10
        )
        p2.pack(fill=tk.BOTH, expand=True)

        desc2 = tk.Label(
            p2,
            text="Simulate attacks and protocol payloads in-memory without sending raw frames onto the network:\n"
                 "• ARP Spoof: baseline IP mapping followed by rogue conflicting MAC\n"
                 "• Port Scan: 25 distinct TCP SYN probes in < 1 second\n"
                 "• Credential Hunter: unencrypted HTTP Basic Auth & HTTP POST login forms",
            font=("Segoe UI", 8),
            justify=tk.LEFT,
            bg=self.colors["card_bg"],
            fg="#abb2bf"
        )
        desc2.pack(anchor=tk.W, pady=(0, 6))

        btn_row = tk.Frame(p2, bg=self.colors["card_bg"])
        btn_row.pack(anchor=tk.W, pady=4)

        btn_test_arp = tk.Button(
            btn_row,
            text="1. Test ARP Spoof",
            command=self.run_arp_test,
            bg="#2e7d32",
            fg="white",
            font=("Segoe UI", 8, "bold"),
            relief="flat",
            padx=8,
            pady=4,
            cursor="hand2"
        )
        btn_test_arp.pack(side=tk.LEFT, padx=(0, 5))

        btn_test_scan = tk.Button(
            btn_row,
            text="2. Test Port Scan (25 SYNs)",
            command=self.run_port_scan_test,
            bg="#e67e22",
            fg="white",
            font=("Segoe UI", 8, "bold"),
            relief="flat",
            padx=8,
            pady=4,
            cursor="hand2"
        )
        btn_test_scan.pack(side=tk.LEFT, padx=5)

        btn_test_cred = tk.Button(
            btn_row,
            text="3. Test Credential Hunter",
            command=self.run_cred_test,
            bg="#8e44ad",
            fg="white",
            font=("Segoe UI", 8, "bold"),
            relief="flat",
            padx=8,
            pady=4,
            cursor="hand2"
        )
        btn_test_cred.pack(side=tk.LEFT, padx=5)

        btn_test_all = tk.Button(
            btn_row,
            text="⚡ Run All 3 Tests",
            command=self.run_all_tests,
            bg="#4c78dd",
            fg="white",
            font=("Segoe UI", 8, "bold"),
            relief="flat",
            padx=10,
            pady=4,
            cursor="hand2"
        )
        btn_test_all.pack(side=tk.LEFT, padx=5)

        self.test_output = tk.Text(
            p2,
            height=6,
            bg="#181a1f",
            fg="#98c379",
            font=("Consolas", 9),
            relief="flat"
        )
        self.test_output.pack(fill=tk.BOTH, expand=True, pady=4)

    # ------------------ Sniffing Logic ------------------

    def get_selected_interface_device(self):
        label = self.iface_var.get()
        return self.interfaces.get(label, conf.iface)

    def start_sniffing(self):
        if self.is_sniffing:
            return

        iface_dev = self.get_selected_interface_device()
        bpf_filter = self.filter_var.get().strip()

        self.is_sniffing = True
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.iface_combo.config(state=tk.DISABLED)
        self.filter_entry.config(state=tk.DISABLED)

        self.status_badge.config(text="● STATUS: SNIFFING ACTIVE", bg="#2e7d32", fg="#ffffff")
        self.lbl_footer.config(text=f"Sniffing on '{self.iface_var.get()}' with filter '{bpf_filter}'...")

        self.log_stream(f"[*] Started sniffing on {iface_dev} (Filter: {bpf_filter})\n", "SYSTEM")

        self.sniff_thread = threading.Thread(
            target=self.sniff_worker,
            args=(iface_dev, bpf_filter),
            daemon=True
        )
        self.sniff_thread.start()

    def stop_sniffing(self):
        if not self.is_sniffing:
            return

        self.is_sniffing = False
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.iface_combo.config(state="readonly")
        self.filter_entry.config(state=tk.NORMAL)

        self.status_badge.config(text="● STATUS: STOPPED", bg="#f57c00", fg="#ffffff")
        self.lbl_footer.config(text="Sniffer stopped.")
        self.log_stream("[*] Sniffing stopped by user.\n", "SYSTEM")

    def sniff_worker(self, iface_dev, bpf_filter):
        """Background thread worker to sniff packets safely."""
        try:
            while self.is_sniffing:
                sniff(
                    iface=iface_dev,
                    filter=bpf_filter,
                    prn=self.packet_handler,
                    store=False,
                    timeout=1,
                    stop_filter=lambda p: not self.is_sniffing
                )
        except Exception as e:
            self.msg_queue.put(("ERROR", f"Sniffer error on interface: {e}"))
        finally:
            self.msg_queue.put(("STOPPED", None))

    def packet_handler(self, packet):
        """Called by Scapy for every sniffed packet."""
        self.msg_queue.put(("PACKET_RAW", packet.summary()))
        # Dispatch to full AnomalySnifferCLI engine
        self.engine.packet_callback(packet)

    # ------------------ Queue Processing & UI Updates ------------------

    def process_queue(self):
        """Process messages sent from background threads to Tkinter main thread."""
        try:
            while True:
                msg_type, data = self.msg_queue.get_nowait()

                if msg_type == "PACKET_RAW":
                    self.total_packets += 1
                    self.stat_cards["total"].config(text=str(self.total_packets))
                    self.log_stream(f"[{datetime.now().strftime('%H:%M:%S')}] {data}\n")

                elif msg_type == "ARP_UPDATE":
                    self.arp_packets += 1
                    self.stat_cards["arp"].config(text=str(self.arp_packets))

                    ip = data["ip"]
                    mac = data["mac"]
                    now_str = data["timestamp"]

                    if ip in self.hosts:
                        self.hosts[ip]["count"] += 1
                        self.hosts[ip]["last_seen"] = now_str
                    else:
                        self.hosts[ip] = {
                            "mac": mac,
                            "first_seen": now_str,
                            "last_seen": now_str,
                            "count": 1,
                            "status": "Verified Host"
                        }

                    self.stat_cards["hosts"].config(text=str(len(self.hosts)))
                    self.refresh_arp_tree()
                    self.log_stream(f"[ARP] Learned/Confirmed: {ip} -> {mac}\n", "ARP")

                elif msg_type in ("ALERT", "ALERT_ARP"):
                    self.alert_count += 1
                    self.stat_cards["alerts"].config(text=str(self.alert_count))

                    ip = data["ip"]
                    now_str = data["timestamp"]

                    # Update host status in cache table
                    if ip in self.hosts:
                        self.hosts[ip]["status"] = "⚠️ SPOOFING DETECTED"
                        self.hosts[ip]["last_seen"] = now_str
                    else:
                        self.hosts[ip] = {
                            "mac": data["original_mac"],
                            "first_seen": now_str,
                            "last_seen": now_str,
                            "count": 1,
                            "status": "⚠️ SPOOFING DETECTED"
                        }

                    self.alerts.append(data)
                    self.alert_tree.insert(
                        "",
                        0,
                        values=(
                            data["timestamp"],
                            data["ip"],
                            data["original_mac"],
                            data["attacker_mac"],
                            "CRITICAL / ARP"
                        ),
                        tags=("critical",)
                    )

                    # Update alert details pane
                    self.show_alert_details(data)

                    self.refresh_arp_tree()
                    self.log_stream(
                        f"\n{'!'*40}\n[!] ALERT: ARP SPOOFING DETECTED!\n"
                        f"    Target IP   : {data['ip']}\n"
                        f"    Original MAC: {data['original_mac']}\n"
                        f"    Attacker MAC: {data['attacker_mac']}\n"
                        f"{'!'*40}\n",
                        "ALERT"
                    )

                    # Highlight alerts tab
                    self.notebook.tab(self.tab_alerts, text=f"  🚨 Alerts ({self.alert_count})  ")

                elif msg_type == "ALERT_SCAN":
                    self.alert_count += 1
                    self.stat_cards["alerts"].config(text=str(self.alert_count))
                    self.alerts.append(data)
                    self.alert_tree.insert(
                        "",
                        0,
                        values=(
                            data["timestamp"],
                            data["scanner_ip"],
                            f"Target: {data['target_ip']}",
                            f"{data['count']} SYN Probes",
                            "HIGH / SCAN"
                        ),
                        tags=("critical",)
                    )
                    self.alert_detail_text.delete("1.0", tk.END)
                    self.alert_detail_text.insert(
                        tk.END,
                        f"=== PORT SCAN INCIDENT REPORT ===\n"
                        f"Timestamp     : {data['timestamp']}\n"
                        f"Scanner IP    : {data['scanner_ip']}\n"
                        f"Target IP     : {data['target_ip']}\n"
                        f"SYN Probes    : {data['count']} distinct ports probed within sliding window\n"
                        f"Ports Sample  : {', '.join(map(str, data['ports'][:10]))}...\n"
                        f"Recommended Remediation:\n"
                        f"  1. Configure firewall rate limiting for inbound SYN probes.\n"
                        f"  2. Temporarily blackhole or drop traffic from {data['scanner_ip']}.\n"
                        f"  3. Enable Fail2Ban or intrusion prevention (IPS) rules.\n"
                    )
                    self.log_stream(
                        f"\n{'!'*40}\n[!] ALERT: PORT SCAN DETECTED!\n"
                        f"    Scanner: {data['scanner_ip']} -> Target: {data['target_ip']}\n"
                        f"    Probed : {data['count']} ports in 5.0s\n"
                        f"{'!'*40}\n",
                        "ALERT"
                    )
                    self.notebook.tab(self.tab_alerts, text=f"  🚨 Alerts ({self.alert_count})  ")

                elif msg_type == "CREDENTIAL":
                    self.alert_count += 1
                    self.stat_cards["alerts"].config(text=str(self.alert_count))
                    self.alerts.append(data)
                    self.alert_tree.insert(
                        "",
                        0,
                        values=(
                            data["timestamp"],
                            data["src_ip"],
                            f"Protocol: {data['protocol']}",
                            f"User: {data['user']} | Pass: {data['pass']}",
                            "EXPOSED CREDS"
                        ),
                        tags=("critical",)
                    )
                    self.alert_detail_text.delete("1.0", tk.END)
                    self.alert_detail_text.insert(
                        tk.END,
                        f"=== EXPOSED CREDENTIAL REPORT ===\n"
                        f"Timestamp     : {data['timestamp']}\n"
                        f"Protocol      : {data['protocol']}\n"
                        f"Source IP     : {data['src_ip']} -> Target IP: {data['dst_ip']}\n"
                        f"Username      : {data['user']}\n"
                        f"Password      : {data['pass']}\n"
                        f"Recommended Remediation:\n"
                        f"  1. Disable unencrypted HTTP/FTP/Telnet on servers.\n"
                        f"  2. Enforce HTTPS/TLS and replace FTP/Telnet with SFTP and SSH.\n"
                        f"  3. Rotate exposed passwords immediately.\n"
                    )
                    self.log_stream(
                        f"\n{'*'*40}\n[*] CREDENTIAL INTERCEPTED!\n"
                        f"    Protocol: {data['protocol']}\n"
                        f"    User    : {data['user']}\n"
                        f"    Pass    : {data['pass']}\n"
                        f"{'*'*40}\n",
                        "ALERT"
                    )
                    self.notebook.tab(self.tab_alerts, text=f"  🚨 Alerts ({self.alert_count})  ")

                elif msg_type == "ERROR":
                    messagebox.showerror("Sniffer Error", str(data))
                    self.stop_sniffing()

                elif msg_type == "STOPPED":
                    if self.is_sniffing:
                        self.stop_sniffing()

        except queue.Empty:
            pass

        # Schedule next queue check
        self.root.after(100, self.process_queue)

    def refresh_arp_tree(self):
        """Update items in the ARP Table treeview, applying search filter."""
        query = self.arp_search_var.get().strip().lower()

        for item in self.arp_tree.get_children():
            self.arp_tree.delete(item)

        for ip, info in sorted(self.hosts.items()):
            if query and (query not in ip.lower() and query not in info["mac"].lower()):
                continue

            tag = "conflict" if "SPOOFING" in info["status"] else "normal"
            self.arp_tree.insert(
                "",
                tk.END,
                values=(
                    ip,
                    info["mac"],
                    info["count"],
                    info["first_seen"],
                    info["last_seen"],
                    info["status"]
                ),
                tags=(tag,)
            )

    def show_alert_details(self, alert_data):
        self.alert_detail_text.delete("1.0", tk.END)
        details = (
            f"=== SECURITY INCIDENT REPORT ===\n"
            f"Timestamp     : {alert_data['timestamp']}\n"
            f"Target IP     : {alert_data['ip']} (Known legitimate MAC: {alert_data['original_mac']})\n"
            f"Rogue Source  : Conflict detected with MAC {alert_data['attacker_mac']}\n"
            f"Threat Type   : Man-In-The-Middle (MitM) ARP Cache Poisoning Attack\n"
            f"Impact        : Network traffic destined for {alert_data['ip']} may be intercepted/tampered.\n"
            f"Recommended Remediation:\n"
            f"  1. Isolate the network port matching MAC {alert_data['attacker_mac']}.\n"
            f"  2. Enable Dynamic ARP Inspection (DAI) and DHCP Snooping on local switches.\n"
            f"  3. Configure static ARP entries for critical gateway routers.\n"
        )
        self.alert_detail_text.insert(tk.END, details)

    def on_alert_selected(self, event):
        selected = self.alert_tree.selection()
        if not selected:
            return
        item = self.alert_tree.item(selected[0])
        vals = item.get("values", [])
        if len(vals) >= 4:
            alert_data = {
                "timestamp": vals[0],
                "ip": vals[1],
                "original_mac": vals[2],
                "attacker_mac": vals[3]
            }
            self.show_alert_details(alert_data)

    def log_stream(self, text, tag=None):
        if tag:
            self.packet_text.insert(tk.END, text, tag)
        else:
            self.packet_text.insert(tk.END, text)

        # Keep buffer bounded to prevent unbounded memory growth
        line_count = int(self.packet_text.index('end-1c').split('.')[0])
        if line_count > 1500:
            self.packet_text.delete('1.0', '300.0')

        if self.autoscroll_var.get():
            self.packet_text.see(tk.END)

    def clear_packet_stream(self):
        self.packet_text.delete("1.0", tk.END)

    def flush_arp_cache(self):
        arp_cache.clear()
        self.hosts.clear()
        self.stat_cards["hosts"].config(text="0")
        self.refresh_arp_tree()
        self.log_stream("[*] Local ARP cache flushed.\n", "SYSTEM")

    def clear_all(self):
        self.total_packets = 0
        self.arp_packets = 0
        self.alert_count = 0
        self.stat_cards["total"].config(text="0")
        self.stat_cards["arp"].config(text="0")
        self.stat_cards["hosts"].config(text="0")
        self.stat_cards["alerts"].config(text="0")

        self.flush_arp_cache()
        self.clear_packet_stream()

        for item in self.alert_tree.get_children():
            self.alert_tree.delete(item)
        self.alerts.clear()
        self.notebook.tab(self.tab_alerts, text="  🚨 Security Alerts  ")
        self.alert_detail_text.delete("1.0", tk.END)
        self.alert_detail_text.insert(tk.END, "Alert log cleared.")

    def export_report(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("Text Files", "*.txt"), ("All Files", "*.*")],
            title="Export Sniffer Security Report"
        )
        if not file_path:
            return

        report_data = {
            "exported_at": datetime.now().isoformat(),
            "summary": {
                "total_packets": self.total_packets,
                "arp_packets": self.arp_packets,
                "cached_hosts_count": len(self.hosts),
                "alerts_count": len(self.alerts)
            },
            "arp_cache": self.hosts,
            "security_alerts": self.alerts
        }

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=4)
            messagebox.showinfo("Export Successful", f"Security report successfully saved to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Could not save report: {e}")

    # ------------------ Simulation & Verification ------------------

    def generate_random_mac(self):
        mac = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
        self.sim_mac_var.set(mac)

    def select_cached_ip_for_sim(self):
        if not self.hosts:
            messagebox.showinfo("No Cached IPs", "No devices in the ARP cache yet. Enter an IP manually.")
            return

        selected_ip = list(self.hosts.keys())[0]
        # Prefer an IP with multiple packets or first in list
        self.sim_ip_var.set(selected_ip)
        messagebox.showinfo("Target IP Selected", f"Populated Target IP with cached host: {selected_ip}")

    def execute_sim_injection(self):
        target_ip = self.sim_ip_var.get().strip()
        fake_mac = self.sim_mac_var.get().strip()

        if not target_ip or not fake_mac:
            messagebox.showwarning("Missing Input", "Please provide both Target IP and Rogue MAC.")
            return

        iface_dev = self.get_selected_interface_device()

        confirm = messagebox.askyesno(
            "Confirm Packet Injection",
            f"Are you sure you want to send a spoofed ARP frame?\n\nTarget IP: {target_ip}\nRogue MAC: {fake_mac}\nInterface: {iface_dev}"
        )
        if not confirm:
            return

        try:
            send_spoof_packet(target_ip, fake_mac, count=1, iface=iface_dev)
            self.log_stream(f"[+] Injected spoofed frame: {target_ip} is at {fake_mac}\n", "SYSTEM")
            messagebox.showinfo("Injected", f"Successfully transmitted 1 spoofed ARP frame for {target_ip}.")
        except Exception as e:
            messagebox.showerror(
                "Injection Error",
                f"Failed to transmit frame: {e}\n(Ensure you run as Administrator or Npcap is enabled for raw frame transmission)."
            )

    def run_arp_test(self):
        """Simulate ARP Spoof in memory."""
        self.test_output.delete("1.0", tk.END)
        self.test_output.insert(tk.END, "[*] Running Test 1: ARP Spoof Anomaly...\n")
        legit_pkt = ARP(op=2, psrc="192.168.1.1", hwsrc="11:11:11:11:11:11")
        self.packet_handler(legit_pkt)

        spoof_pkt = ARP(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff")
        self.packet_handler(spoof_pkt)
        self.test_output.insert(tk.END, "[✓] Injected legitimate baseline + conflicting rogue MAC packet.\nCheck 'Security Alerts' tab.\n")

    def run_port_scan_test(self):
        """Simulate 25 TCP SYN probes in memory."""
        from scapy.all import IP, TCP
        self.test_output.delete("1.0", tk.END)
        self.test_output.insert(tk.END, "[*] Running Test 2: Port Scan (25 distinct SYNs)...\n")
        attacker_ip = "10.0.0.99"
        for port in range(1, 26):
            syn_pkt = IP(src=attacker_ip, dst="192.168.1.1") / TCP(sport=50000 + port, dport=port, flags="S")
            self.packet_handler(syn_pkt)
        self.test_output.insert(tk.END, f"[✓] Injected 25 SYN probes from {attacker_ip}.\nCheck 'Security Alerts' tab for Port Scan alert.\n")

    def run_cred_test(self):
        """Simulate HTTP Basic Auth & POST Form credentials in memory."""
        from scapy.all import IP, TCP, Raw
        self.test_output.delete("1.0", tk.END)
        self.test_output.insert(tk.END, "[*] Running Test 3: Credential Hunter (HTTP Basic + POST)...\n")
        b64 = base64.b64encode(b"admin:SecretPass123").decode()
        http_data = f"GET /admin HTTP/1.1\r\nAuthorization: Basic {b64}\r\n\r\n".encode()
        pkt1 = IP(src="192.168.1.50", dst="192.168.1.1") / TCP(sport=52100, dport=80) / Raw(load=http_data)
        self.packet_handler(pkt1)

        post_data = b"POST /login HTTP/1.1\r\n\r\nusername=finance_user&password=Password2026!"
        pkt2 = IP(src="192.168.1.60", dst="192.168.1.200") / TCP(sport=52101, dport=8080) / Raw(load=post_data)
        self.packet_handler(pkt2)
        self.test_output.insert(tk.END, "[✓] Injected HTTP Basic Auth and POST form packets.\nCheck 'Security Alerts' tab for intercepted credentials.\n")

    def run_all_tests(self):
        self.run_arp_test()
        self.run_port_scan_test()
        self.run_cred_test()
        self.test_output.insert(tk.END, "\n[✓] ALL 3 IN-MEMORY TESTS COMPLETED!\n")

    def run_in_memory_test(self):
        self.run_all_tests()

    def on_closing(self):
        if self.is_sniffing:
            self.stop_sniffing()
            time.sleep(0.3)
        self.root.destroy()


def main():
    root = tk.Tk()
    app = ArpSnifferGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

