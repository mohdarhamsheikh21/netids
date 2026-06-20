#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║   NetIDS — Network Packet Analyzer & Intrusion Detection ║
║   Blue Team tool for real-time traffic monitoring        ║
║                                                          ║
║   Detects:                                               ║
║     • SYN Flood          • Port Scan                     ║
║     • Brute Force        • ICMP Flood                    ║
║     • UDP Flood          • ARP Spoofing                  ║
║                                                          ║
║   Usage (requires root):                                 ║
║     sudo python3 netids.py -i eth0                       ║
║     sudo python3 netids.py -i eth0 -t 60 -o alerts.txt  ║
║     sudo python3 netids.py --list-interfaces             ║
║                                                          ║
║   Install deps:  pip install scapy colorama              ║
╚══════════════════════════════════════════════════════════╝
"""

import argparse
import json
import os
import sys
import time
from collections import defaultdict, Counter
from datetime import datetime
from threading import Lock

# ── Dependency checks ──────────────────────────────────────────────
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, get_if_list
except ImportError:
    print("[ERROR] Scapy not installed. Run: pip install scapy")
    sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    C = {
        "RED":     Fore.RED,
        "GREEN":   Fore.GREEN,
        "YELLOW":  Fore.YELLOW,
        "CYAN":    Fore.CYAN,
        "MAGENTA": Fore.MAGENTA,
        "BOLD":    Style.BRIGHT,
        "DIM":     Style.DIM,
        "RESET":   Style.RESET_ALL,
    }
    COLORS = True
except ImportError:
    # Graceful fallback if colorama not installed
    C = {k: "" for k in ["RED", "GREEN", "YELLOW", "CYAN", "MAGENTA", "BOLD", "DIM", "RESET"]}
    COLORS = False


# ══════════════════════════════════════════════════════════════════
# CONFIGURATION — Edit these thresholds to tune sensitivity
# ══════════════════════════════════════════════════════════════════

THRESHOLDS = {
    # How many events from one IP within the time window triggers an alert
    "syn_flood":   {"count": 50,  "window": 10},  # 50 SYN pkts from 1 IP in 10s
    "port_scan":   {"count": 15,  "window": 10},  # 15 unique ports from 1 IP in 10s
    "brute_force": {"count": 10,  "window": 30},  # 10 attempts to same port in 30s
    "icmp_flood":  {"count": 30,  "window": 10},  # 30 ICMP pkts from 1 IP in 10s
    "udp_flood":   {"count": 100, "window": 10},  # 100 UDP pkts from 1 IP in 10s
}

# Ports commonly targeted in brute-force attacks
BRUTE_FORCE_PORTS = {
    22:   "SSH",
    21:   "FTP",
    23:   "Telnet",
    3389: "RDP",
    5900: "VNC",
    25:   "SMTP",
    110:  "POP3",
    143:  "IMAP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
}

# Severity → display label mapping
SEVERITY_LABEL = {
    "HIGH":   f"{C['BOLD']}{C['RED']}[HIGH]  {C['RESET']}",
    "MEDIUM": f"{C['BOLD']}{C['YELLOW']}[MED]   {C['RESET']}",
    "LOW":    f"{C['BOLD']}{C['CYAN']}[LOW]   {C['RESET']}",
}


# ══════════════════════════════════════════════════════════════════
# Alert — one detected threat event
# ══════════════════════════════════════════════════════════════════

class Alert:
    """
    Represents a single IDS detection event.

    Each alert stores what was detected, where it came from,
    how severe it is, and the evidence that triggered it.
    """
    def __init__(self, alert_type, src_ip, dst_ip, severity, details, dst_port=None):
        self.timestamp  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.alert_type = alert_type   # e.g. "SYN FLOOD", "PORT SCAN"
        self.src_ip     = src_ip       # Attacker's IP
        self.dst_ip     = dst_ip       # Target IP
        self.dst_port   = dst_port     # Target port (if applicable)
        self.severity   = severity     # "HIGH", "MEDIUM", "LOW"
        self.details    = details      # Human-readable evidence string

    def to_dict(self):
        """Serialize to dict for JSON report output."""
        return {
            "timestamp":  self.timestamp,
            "type":       self.alert_type,
            "severity":   self.severity,
            "src_ip":     self.src_ip,
            "dst_ip":     self.dst_ip,
            "dst_port":   self.dst_port,
            "details":    self.details,
        }

    def __str__(self):
        """Formatted one-line string for console output."""
        port_str = f":{self.dst_port}" if self.dst_port else ""
        return (
            f"{SEVERITY_LABEL[self.severity]}"
            f"{C['BOLD']}{self.timestamp}{C['RESET']} │ "
            f"{C['MAGENTA']}{self.alert_type:<20}{C['RESET']} │ "
            f"{C['CYAN']}{self.src_ip}{C['RESET']} → "
            f"{self.dst_ip}{port_str} │ "
            f"{self.details}"
        )

    def to_plain_str(self):
        """Same as __str__ but with no ANSI codes — for writing to log files."""
        port_str = f":{self.dst_port}" if self.dst_port else ""
        return (
            f"[{self.severity}] {self.timestamp} | "
            f"{self.alert_type:<20} | "
            f"{self.src_ip} -> {self.dst_ip}{port_str} | "
            f"{self.details}"
        )


# ══════════════════════════════════════════════════════════════════
# TrafficTracker — per-IP sliding-window packet counters
# ══════════════════════════════════════════════════════════════════

class TrafficTracker:
    """
    Keeps a rolling record of events per IP address.

    For each detection type, we store a list of (timestamp, ...) tuples
    per source IP. Before counting, we discard events older than the
    relevant time window — this is the "sliding window" technique.

    Example:
        SYN flood window = 10 seconds.
        IP 192.168.1.5 sends SYN packets at t=0, 1, 2, ... 9s → 10 entries.
        At t=11s the first entry (t=0) is pruned.
        Count at any moment = SYNs from that IP in the last 10 seconds.
    """
    def __init__(self):
        self._lock = Lock()  # Thread-safe for use with Scapy's async sniff

        # Per-IP event lists: each entry is (unix_timestamp, optional_data)
        self.syn_events    = defaultdict(list)   # src_ip → [(t,)]
        self.port_contacts = defaultdict(list)   # src_ip → [(t, dst_port)]
        self.brute_events  = defaultdict(list)   # (src_ip, dst_port) → [(t,)]
        self.icmp_events   = defaultdict(list)   # src_ip → [(t,)]
        self.udp_events    = defaultdict(list)   # src_ip → [(t,)]

        # ARP table: ip → mac, used to detect conflicting mappings
        self.arp_table = {}

        # Global counters for the final report
        self.proto_counts  = Counter()   # {"TCP": n, "UDP": n, ...}
        self.total_packets = 0
        self.start_time    = time.time()

    def _prune(self, event_list, window_secs):
        """
        Remove stale entries from the front of a sorted event list.
        Lists are appended in time order, so stale items are always at index 0.
        """
        cutoff = time.time() - window_secs
        while event_list and event_list[0][0] < cutoff:
            event_list.pop(0)

    # ── Individual record methods ──────────────────────────────────

    def record_syn(self, src_ip):
        """Record a SYN packet. Returns current count in window."""
        with self._lock:
            self.syn_events[src_ip].append((time.time(),))
            self._prune(self.syn_events[src_ip], THRESHOLDS["syn_flood"]["window"])
            return len(self.syn_events[src_ip])

    def record_port_contact(self, src_ip, dst_port):
        """Record a connection attempt. Returns number of unique ports in window."""
        with self._lock:
            self.port_contacts[src_ip].append((time.time(), dst_port))
            self._prune(self.port_contacts[src_ip], THRESHOLDS["port_scan"]["window"])
            # Count only unique destination ports
            unique = len(set(e[1] for e in self.port_contacts[src_ip]))
            return unique

    def record_brute(self, src_ip, dst_port):
        """Record a connection attempt to a sensitive port. Returns count in window."""
        key = (src_ip, dst_port)
        with self._lock:
            self.brute_events[key].append((time.time(),))
            self._prune(self.brute_events[key], THRESHOLDS["brute_force"]["window"])
            return len(self.brute_events[key])

    def record_icmp(self, src_ip):
        """Record an ICMP packet. Returns count in window."""
        with self._lock:
            self.icmp_events[src_ip].append((time.time(),))
            self._prune(self.icmp_events[src_ip], THRESHOLDS["icmp_flood"]["window"])
            return len(self.icmp_events[src_ip])

    def record_udp(self, src_ip):
        """Record a UDP packet. Returns count in window."""
        with self._lock:
            self.udp_events[src_ip].append((time.time(),))
            self._prune(self.udp_events[src_ip], THRESHOLDS["udp_flood"]["window"])
            return len(self.udp_events[src_ip])

    def check_arp_spoof(self, ip, mac):
        """
        Check if this (IP, MAC) pair conflicts with a previously seen mapping.

        ARP Spoofing works by sending fake ARP replies that say "IP X is at
        MAC Y", overwriting the victim's ARP cache to redirect traffic.
        We detect it by noting when the same IP suddenly maps to a new MAC.

        Returns True if a conflict is detected (possible spoofing).
        """
        with self._lock:
            if ip in self.arp_table:
                if self.arp_table[ip] != mac:
                    return True   # Same IP, different MAC = conflict
            else:
                self.arp_table[ip] = mac
            return False


# ══════════════════════════════════════════════════════════════════
# NetIDS — Core detection engine
# ══════════════════════════════════════════════════════════════════

class NetIDS:
    """
    Main IDS class. Uses Scapy to capture packets and routes each one
    through detection modules. Raises alerts in real time and generates
    a full report when capture ends.
    """
    def __init__(self, interface, output_file, verbose=False):
        self.interface   = interface
        self.output_file = output_file
        self.verbose     = verbose
        self.tracker     = TrafficTracker()
        self.alerts      = []
        self._lock       = Lock()

        # Cooldown set: prevents the same IP from spamming the same alert type.
        # Stores strings like "syn_flood_192.168.1.5"
        self.alerted     = set()

        # Open the text log file
        self.log_fh = open(output_file, "w", encoding="utf-8") if output_file else None

    # ── Alert dispatch ─────────────────────────────────────────────

    def _raise_alert(self, alert: Alert, cooldown_key: str = None):
        """
        Dispatch an alert: print to console, write to log, store in list.

        cooldown_key: if provided, this alert type+IP combo will only fire once.
        """
        if cooldown_key and cooldown_key in self.alerted:
            return  # Suppress duplicate alert for same IP + type
        if cooldown_key:
            self.alerted.add(cooldown_key)

        with self._lock:
            self.alerts.append(alert)

        # Print to terminal
        print(str(alert))

        # Write plain (no ANSI) version to log file
        if self.log_fh:
            self.log_fh.write(alert.to_plain_str() + "\n")
            self.log_fh.flush()

    # ── Packet router ──────────────────────────────────────────────

    def process_packet(self, pkt):
        """
        Called by Scapy for every captured packet.
        Routes to the correct detection module(s) based on protocol layers.
        """
        self.tracker.total_packets += 1

        # ── ARP: check for spoofing ───────────────────────────────
        if pkt.haslayer(ARP):
            self.tracker.proto_counts["ARP"] += 1
            self._detect_arp_spoof(pkt)
            return  # ARP has no IP layer, nothing else to check

        # Skip non-IP packets (e.g. raw Ethernet)
        if not pkt.haslayer(IP):
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        # ── TCP: SYN flood, port scan, brute force ────────────────
        if pkt.haslayer(TCP):
            self.tracker.proto_counts["TCP"] += 1
            dst_port = pkt[TCP].dport
            flags    = pkt[TCP].flags

            # SYN=1, ACK=0 → this is a new connection initiation (not a handshake reply)
            if (flags & 0x02) and not (flags & 0x10):
                self._detect_syn_flood(pkt, src_ip, dst_ip)
                self._detect_port_scan(pkt, src_ip, dst_ip, dst_port)
                if dst_port in BRUTE_FORCE_PORTS:
                    self._detect_brute_force(pkt, src_ip, dst_ip, dst_port)

        # ── UDP: flood detection ──────────────────────────────────
        elif pkt.haslayer(UDP):
            self.tracker.proto_counts["UDP"] += 1
            self._detect_udp_flood(pkt, src_ip, dst_ip)

        # ── ICMP: ping flood detection ────────────────────────────
        elif pkt.haslayer(ICMP):
            self.tracker.proto_counts["ICMP"] += 1
            self._detect_icmp_flood(pkt, src_ip, dst_ip)

        else:
            self.tracker.proto_counts["OTHER"] += 1

        # Print live stats every 200 packets in verbose mode
        if self.verbose and self.tracker.total_packets % 200 == 0:
            self._print_live_stats()

    # ══════════════════════════════════════════════════════════════
    # Detection modules
    # ══════════════════════════════════════════════════════════════

    def _detect_syn_flood(self, pkt, src_ip, dst_ip):
        """
        SYN Flood: An attacker sends thousands of SYN packets without
        completing the TCP handshake (never sends ACK). This exhausts the
        target's connection table, causing a Denial of Service.

        Detection: Count SYN-only packets from same source IP in a
        sliding time window. Exceeding the threshold = alert.
        """
        count = self.tracker.record_syn(src_ip)
        if count >= THRESHOLDS["syn_flood"]["count"]:
            alert = Alert(
                alert_type = "SYN FLOOD",
                src_ip     = src_ip,
                dst_ip     = dst_ip,
                severity   = "HIGH",
                dst_port   = pkt[TCP].dport,
                details    = (
                    f"{count} SYN packets in "
                    f"{THRESHOLDS['syn_flood']['window']}s — "
                    f"likely DoS attempt"
                ),
            )
            self._raise_alert(alert, cooldown_key=f"syn_flood_{src_ip}")

    def _detect_port_scan(self, pkt, src_ip, dst_ip, dst_port):
        """
        Port Scan: Attacker sends connection requests to many different ports
        rapidly to discover which services are running (reconnaissance).
        Tools like Nmap do exactly this.

        Detection: Track unique destination ports contacted by each source IP.
        If one IP hits 15+ unique ports in 10 seconds → port scan.
        """
        unique_ports = self.tracker.record_port_contact(src_ip, dst_port)
        if unique_ports >= THRESHOLDS["port_scan"]["count"]:
            alert = Alert(
                alert_type = "PORT SCAN",
                src_ip     = src_ip,
                dst_ip     = dst_ip,
                severity   = "HIGH",
                details    = (
                    f"{unique_ports} unique ports probed in "
                    f"{THRESHOLDS['port_scan']['window']}s — "
                    f"reconnaissance in progress"
                ),
            )
            self._raise_alert(alert, cooldown_key=f"port_scan_{src_ip}")

    def _detect_brute_force(self, pkt, src_ip, dst_ip, dst_port):
        """
        Brute Force: Repeated connection attempts to a sensitive port like
        SSH (22) or RDP (3389), where the attacker is trying many passwords.

        Detection: Count SYN packets from one IP to the same sensitive port.
        10+ attempts in 30 seconds → brute force alert.
        """
        count    = self.tracker.record_brute(src_ip, dst_port)
        svc_name = BRUTE_FORCE_PORTS.get(dst_port, str(dst_port))

        if count >= THRESHOLDS["brute_force"]["count"]:
            alert = Alert(
                alert_type = "BRUTE FORCE",
                src_ip     = src_ip,
                dst_ip     = dst_ip,
                severity   = "MEDIUM",
                dst_port   = dst_port,
                details    = (
                    f"{count} attempts to {svc_name} port {dst_port} in "
                    f"{THRESHOLDS['brute_force']['window']}s — "
                    f"password guessing suspected"
                ),
            )
            self._raise_alert(alert, cooldown_key=f"brute_{src_ip}_{dst_port}")

    def _detect_icmp_flood(self, pkt, src_ip, dst_ip):
        """
        ICMP Flood (Ping Flood): Sending huge volumes of ICMP Echo Requests
        to overwhelm a target. A classic DoS technique.

        Detection: Count ICMP packets from one IP in a sliding window.
        """
        count = self.tracker.record_icmp(src_ip)
        if count >= THRESHOLDS["icmp_flood"]["count"]:
            alert = Alert(
                alert_type = "ICMP FLOOD",
                src_ip     = src_ip,
                dst_ip     = dst_ip,
                severity   = "MEDIUM",
                details    = (
                    f"{count} ICMP packets in "
                    f"{THRESHOLDS['icmp_flood']['window']}s — "
                    f"ping flood suspected"
                ),
            )
            self._raise_alert(alert, cooldown_key=f"icmp_flood_{src_ip}")

    def _detect_udp_flood(self, pkt, src_ip, dst_ip):
        """
        UDP Flood: Sending massive volumes of UDP packets to random ports,
        forcing the target to check for listening applications and reply
        with ICMP 'Destination Unreachable' messages — consuming resources.

        Detection: Count UDP packets from one IP in a sliding window.
        """
        count = self.tracker.record_udp(src_ip)
        if count >= THRESHOLDS["udp_flood"]["count"]:
            alert = Alert(
                alert_type = "UDP FLOOD",
                src_ip     = src_ip,
                dst_ip     = dst_ip,
                severity   = "MEDIUM",
                details    = (
                    f"{count} UDP packets in "
                    f"{THRESHOLDS['udp_flood']['window']}s — "
                    f"UDP flood suspected"
                ),
            )
            self._raise_alert(alert, cooldown_key=f"udp_flood_{src_ip}")

    def _detect_arp_spoof(self, pkt):
        """
        ARP Spoofing (Man-in-the-Middle): An attacker broadcasts fake ARP
        replies saying "IP X is at MAC Y" to overwrite victims' ARP caches,
        so traffic meant for X gets sent to the attacker's machine instead.

        Detection: We build an IP→MAC table as we see ARP replies. If we
        see the same IP claim a *different* MAC than what we recorded before,
        that's a conflict — a strong sign of ARP spoofing.
        """
        # ARP op=2 means "is-at" (reply), op=1 means "who-has" (request)
        if pkt[ARP].op == 2:
            sender_ip  = pkt[ARP].psrc   # IP claiming ownership
            sender_mac = pkt[ARP].hwsrc  # MAC it claims to be at

            if self.tracker.check_arp_spoof(sender_ip, sender_mac):
                alert = Alert(
                    alert_type = "ARP SPOOFING",
                    src_ip     = sender_ip,
                    dst_ip     = pkt[ARP].pdst,
                    severity   = "HIGH",
                    details    = (
                        f"Conflicting MAC for {sender_ip} → {sender_mac} — "
                        f"possible MITM / ARP cache poisoning"
                    ),
                )
                self._raise_alert(alert, cooldown_key=f"arp_spoof_{sender_ip}")

    # ── Live stats ─────────────────────────────────────────────────

    def _print_live_stats(self):
        """Print a one-line running summary (verbose mode only)."""
        elapsed = max(time.time() - self.tracker.start_time, 1)
        pps = self.tracker.total_packets / elapsed
        print(
            f"{C['DIM']}  ↳ Pkts: {self.tracker.total_packets} │ "
            f"{pps:.1f} pkt/s │ "
            f"TCP:{self.tracker.proto_counts['TCP']} "
            f"UDP:{self.tracker.proto_counts['UDP']} "
            f"ICMP:{self.tracker.proto_counts['ICMP']} │ "
            f"Alerts: {len(self.alerts)}{C['RESET']}"
        )

    # ── Start capture ──────────────────────────────────────────────

    def start(self, count=0, timeout=None):
        """
        Begin packet capture on the configured interface.

        Args:
            count   : Total packets to capture (0 = unlimited)
            timeout : Stop after N seconds (None = unlimited)
        """
        _print_banner()

        print(f"\n{C['GREEN']}{C['BOLD']}[*] Interface  : {self.interface}{C['RESET']}")
        if timeout:
            print(f"{C['GREEN']}[*] Duration   : {timeout}s{C['RESET']}")
        if self.output_file:
            print(f"{C['GREEN']}[*] Alert log  : {self.output_file}{C['RESET']}")
        print(f"{C['GREEN']}[*] Press Ctrl+C to stop and view report{C['RESET']}\n")

        # Column headers
        divider = "─" * 100
        print(divider)
        print(f"{'SEVERITY':<12} {'TIMESTAMP':<21} {'TYPE':<22} {'SOURCE → DEST':<38} DETAILS")
        print(divider)

        try:
            sniff(
                iface   = self.interface,
                prn     = self.process_packet,
                store   = False,      # Don't buffer packets in RAM
                count   = count,
                timeout = timeout,
            )
        except PermissionError:
            print(f"\n{C['RED']}[!] Permission denied. Run with sudo.{C['RESET']}")
            sys.exit(1)
        except KeyboardInterrupt:
            print(f"\n{C['YELLOW']}[*] Capture stopped.{C['RESET']}")
        finally:
            self._generate_report()

    # ── Final report ───────────────────────────────────────────────

    def _generate_report(self):
        """
        Print a full summary report to the terminal and save a
        machine-readable JSON file alongside the text log.
        """
        elapsed = time.time() - self.tracker.start_time
        now     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        border = "═" * 100
        print(f"\n{border}")
        print(f"{C['BOLD']}  NetIDS Report  ─  {now}{C['RESET']}")
        print(border)

        # ── Section 1: Capture summary ────────────────────────────
        print(f"\n{C['BOLD']}  CAPTURE SUMMARY{C['RESET']}")
        print(f"  ├─ Duration       : {elapsed:.1f}s")
        print(f"  ├─ Total packets  : {self.tracker.total_packets}")
        print(f"  ├─ Avg rate       : {self.tracker.total_packets / max(elapsed,1):.1f} pkt/s")
        print(f"  ├─ TCP            : {self.tracker.proto_counts['TCP']}")
        print(f"  ├─ UDP            : {self.tracker.proto_counts['UDP']}")
        print(f"  ├─ ICMP           : {self.tracker.proto_counts['ICMP']}")
        print(f"  ├─ ARP            : {self.tracker.proto_counts['ARP']}")
        alert_color = C['RED'] if self.alerts else C['GREEN']
        print(f"  └─ Total alerts   : {alert_color}{C['BOLD']}{len(self.alerts)}{C['RESET']}")

        if self.alerts:
            # ── Section 2: Alert breakdown ────────────────────────
            print(f"\n{C['BOLD']}  ALERT BREAKDOWN{C['RESET']}")
            type_counts = Counter(a.alert_type for a in self.alerts)
            for alert_type, count in type_counts.most_common():
                bar = "█" * min(count * 3, 40)
                sev = next(a.severity for a in self.alerts if a.alert_type == alert_type)
                sev_color = C['RED'] if sev == "HIGH" else C['YELLOW']
                print(f"  {sev_color}{alert_type:<22}{C['RESET']} {bar}  ({count})")

            # ── Section 3: Top offending IPs ──────────────────────
            print(f"\n{C['BOLD']}  TOP OFFENDING IPs{C['RESET']}")
            ip_counts = Counter(a.src_ip for a in self.alerts)
            for ip, count in ip_counts.most_common(5):
                types = set(a.alert_type for a in self.alerts if a.src_ip == ip)
                print(f"  {C['RED']}{ip:<20}{C['RESET']}  {count} alert(s)  │  {', '.join(types)}")

            # ── Section 4: All alerts listed ──────────────────────
            print(f"\n{C['BOLD']}  ALL ALERTS{C['RESET']}")
            for i, alert in enumerate(self.alerts, 1):
                port_str = f":{alert.dst_port}" if alert.dst_port else ""
                print(
                    f"  [{i:>3}] {alert.timestamp}  "
                    f"{alert.severity:<6}  "
                    f"{alert.alert_type:<22}  "
                    f"{alert.src_ip} → {alert.dst_ip}{port_str}  │  "
                    f"{alert.details}"
                )

        else:
            print(f"\n  {C['GREEN']}[+] No threats detected during capture window.{C['RESET']}")

        # ── Section 5: Learned ARP table ──────────────────────────
        if self.tracker.arp_table:
            print(f"\n{C['BOLD']}  LEARNED ARP TABLE{C['RESET']}")
            for ip, mac in list(self.tracker.arp_table.items())[:15]:
                print(f"  {C['CYAN']}{ip:<18}{C['RESET']} → {mac}")

        print(f"\n{border}\n")

        # ── Save JSON report ──────────────────────────────────────
        base = (self.output_file or "netids").replace(".txt", "")
        json_path = f"{base}_report.json"

        report = {
            "tool":     "NetIDS",
            "scan": {
                "interface":  self.interface,
                "start":      datetime.fromtimestamp(self.tracker.start_time).isoformat(),
                "end":        datetime.now().isoformat(),
                "duration_s": round(elapsed, 2),
            },
            "stats": {
                "total_packets": self.tracker.total_packets,
                "tcp":           self.tracker.proto_counts["TCP"],
                "udp":           self.tracker.proto_counts["UDP"],
                "icmp":          self.tracker.proto_counts["ICMP"],
                "arp":           self.tracker.proto_counts["ARP"],
                "total_alerts":  len(self.alerts),
            },
            "alerts":    [a.to_dict() for a in self.alerts],
            "arp_table": self.tracker.arp_table,
        }

        with open(json_path, "w") as f:
            json.dump(report, f, indent=2)

        print(f"  {C['GREEN']}[+] JSON report saved → {json_path}{C['RESET']}")
        if self.output_file:
            print(f"  {C['GREEN']}[+] Alert log saved  → {self.output_file}{C['RESET']}")

        if self.log_fh:
            self.log_fh.close()


# ══════════════════════════════════════════════════════════════════
# CLI helpers
# ══════════════════════════════════════════════════════════════════

def _print_banner():
    print(f"""
{C['CYAN']}{C['BOLD']}
  ███╗   ██╗███████╗████████╗██╗██████╗ ███████╗
  ████╗  ██║██╔════╝╚══██╔══╝██║██╔══██╗██╔════╝
  ██╔██╗ ██║█████╗     ██║   ██║██║  ██║███████╗
  ██║╚██╗██║██╔══╝     ██║   ██║██║  ██║╚════██║
  ██║ ╚████║███████╗   ██║   ██║██████╔╝███████║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝╚═════╝ ╚══════╝{C['RESET']}
{C['DIM']}  Network Packet Analyzer & Intrusion Detection System
  Detects: SYN Flood · Port Scan · Brute Force · ICMP Flood · UDP Flood · ARP Spoof{C['RESET']}
""")


def _list_interfaces():
    print(f"\n{C['BOLD']}Available network interfaces:{C['RESET']}")
    for iface in get_if_list():
        print(f"  {C['CYAN']}→{C['RESET']}  {iface}")
    print()


def _require_root():
    if os.geteuid() != 0:
        print(f"{C['RED']}[!] Packet capture requires root. Run with sudo.{C['RESET']}")
        sys.exit(1)


# ══════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        prog        = "netids",
        description = "NetIDS — Network Packet Analyzer & Intrusion Detection System",
        epilog      = (
            "Examples:\n"
            "  sudo python3 netids.py -i eth0\n"
            "  sudo python3 netids.py -i eth0 -t 120 -o report.txt\n"
            "  sudo python3 netids.py -i wlan0 --verbose\n"
            "  python3 netids.py --list-interfaces"
        ),
        formatter_class = argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "-i", "--interface",
        default = "eth0",
        help    = "Network interface to listen on (default: eth0)",
    )
    parser.add_argument(
        "-t", "--timeout",
        type    = int,
        default = None,
        help    = "Stop capture after N seconds (default: run until Ctrl+C)",
    )
    parser.add_argument(
        "-c", "--count",
        type    = int,
        default = 0,
        help    = "Stop after capturing N packets (default: 0 = unlimited)",
    )
    parser.add_argument(
        "-o", "--output",
        default = "netids_alerts.txt",
        help    = "File path for the alert log (default: netids_alerts.txt)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action  = "store_true",
        help    = "Print live packet stats every 200 packets",
    )
    parser.add_argument(
        "--list-interfaces",
        action  = "store_true",
        help    = "List available network interfaces and exit",
    )

    args = parser.parse_args()

    if args.list_interfaces:
        _list_interfaces()
        sys.exit(0)

    _require_root()

    ids = NetIDS(
        interface   = args.interface,
        output_file = args.output,
        verbose     = args.verbose,
    )
    ids.start(count=args.count, timeout=args.timeout)


if __name__ == "__main__":
    main()
