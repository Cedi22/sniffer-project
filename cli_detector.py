"""
Custom CLI Network Sniffer & Anomaly Detector
---------------------------------------------
Phase 1 Implementation:
1. ARP Spoof Detector (In-memory IP-to-MAC baseline table, gratuitous ARP conflict alerting)
2. Port Scan Detector (Sliding-window tracker: flags IPs with 20+ distinct SYN requests in 5s)
3. Credential Hunter (Payload inspection for HTTP Basic Auth / POST, FTP USER/PASS, Telnet)
4. ANSI Color-coded real-time timestamped CLI event stream
"""

import sys
import os
import time
import base64
import re
import argparse
from datetime import datetime
from collections import deque, defaultdict

# Ensure ANSI colors work on Windows terminals
if os.name == 'nt':
    os.system('')

# ANSI Colors
class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BG_RED  = "\033[41m"

def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

try:
    from scapy.all import sniff, ARP, IP, TCP, Raw, conf
except Exception as e:
    print(f"{Colors.RED}[-] Failed to load Scapy: {e}{Colors.RESET}")
    sys.exit(1)


class AnomalySnifferCLI:
    def __init__(self, interface=None, scan_threshold=20, scan_window=5.0,
                 on_alert=None, on_cred=None, on_learn=None):
        self.interface = interface or conf.iface
        self.scan_threshold = scan_threshold  # 20 distinct ports
        self.scan_window = scan_window        # 5.0 seconds
        self.on_alert = on_alert
        self.on_cred = on_cred
        self.on_learn = on_learn

        # 1. ARP Spoof Detector Storage: ip -> mac
        self.arp_cache = {}

        # 2. Port Scan Detector Storage: src_ip -> deque([(timestamp, dst_port), ...])
        self.syn_tracker = defaultdict(deque)
        self.last_scan_alert = {}  # src_ip -> timestamp of last alert (rate limit alerts)

        # 3. Credential Hunter Storage
        self.captured_credentials = []

        # Statistics
        self.packet_count = 0
        self.arp_count = 0
        self.syn_count = 0
        self.alert_count = 0

    # -------------------------------------------------------------
    # Detector 1: ARP Spoof / Poison Detector
    # -------------------------------------------------------------
    def process_arp(self, packet):
        """
        Inspects ARP frames. Flags duplicate/conflicting IPs with mismatched MACs.
        """
        if not packet.haslayer(ARP):
            return

        arp = packet[ARP]
        self.arp_count += 1

        # op=1: ARP Request (who-has), op=2: ARP Reply (is-at)
        src_ip = arp.psrc
        src_mac = arp.hwsrc.lower()

        if not src_ip or src_ip == "0.0.0.0":
            return

        if src_ip in self.arp_cache:
            known_mac = self.arp_cache[src_ip]
            if known_mac != src_mac:
                self.alert_count += 1
                ts = get_timestamp()
                alert_data = {
                    "ip": src_ip,
                    "original_mac": known_mac,
                    "attacker_mac": src_mac,
                    "timestamp": ts
                }
                print(f"\n{Colors.BG_RED}{Colors.WHITE}{Colors.BOLD} [!] CRITICAL SECURITY ALERT: ARP SPOOFING DETECTED {Colors.RESET}")
                print(f"{Colors.RED}{Colors.BOLD}[{ts}] TARGET IP   : {Colors.WHITE}{src_ip}{Colors.RESET}")
                print(f"{Colors.RED}{Colors.BOLD}[{ts}] ORIGINAL MAC: {Colors.GREEN}{known_mac}{Colors.RESET}")
                print(f"{Colors.RED}{Colors.BOLD}[{ts}] ATTACKER MAC: {Colors.YELLOW}{src_mac}{Colors.RESET}")
                print(f"{Colors.RED}[{ts}] THREAT      : Man-In-The-Middle (MitM) Cache Poisoning / Duplicate IP Claim{Colors.RESET}")
                print(f"{Colors.RED}{'-' * 65}{Colors.RESET}\n")
                if self.on_alert:
                    self.on_alert("ALERT_ARP", alert_data)
                return ("ALERT_ARP", src_ip, known_mac, src_mac)
        else:
            self.arp_cache[src_ip] = src_mac
            ts = get_timestamp()
            print(f"{Colors.CYAN}[{ts}] [ARP-LEARN]{Colors.RESET} Baseline mapped: {Colors.WHITE}{src_ip}{Colors.RESET} -> {Colors.YELLOW}{src_mac}{Colors.RESET}")
            if self.on_learn:
                self.on_learn({"ip": src_ip, "mac": src_mac, "timestamp": ts})
            return ("LEARN_ARP", src_ip, src_mac)

    # -------------------------------------------------------------
    # Detector 2: Port Scan Detector (SYN Sliding Window)
    # -------------------------------------------------------------
    def process_port_scan(self, packet):
        """
        Sliding-window tracker flagging IPs exceeding 20+ distinct SYN requests in 5 seconds.
        """
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return

        tcp = packet[TCP]
        ip = packet[IP]

        # Check for SYN flag set, ACK flag NOT set (initial handshake probe)
        # In Scapy: tcp.flags can be evaluated as an integer bitmask (SYN=0x02, ACK=0x10) or string 'S'
        flags = tcp.flags
        is_syn = (flags & 0x02) and not (flags & 0x10)
        if not is_syn:
            return

        self.syn_count += 1
        src_ip = ip.src
        dst_port = tcp.dport
        now = time.time()

        queue = self.syn_tracker[src_ip]
        queue.append((now, dst_port))

        # Evict records older than the sliding window (e.g. older than now - 5 seconds)
        cutoff = now - self.scan_window
        while queue and queue[0][0] < cutoff:
            queue.popleft()

        # Count distinct destination ports in the current window
        distinct_ports = {dport for _, dport in queue}

        if len(distinct_ports) >= self.scan_threshold:
            # Rate-limit alert to once every 4 seconds per scanner IP
            last_alert = self.last_scan_alert.get(src_ip, 0)
            if now - last_alert >= 4.0:
                self.last_scan_alert[src_ip] = now
                self.alert_count += 1
                ts = get_timestamp()
                sample_ports = sorted(list(distinct_ports))[:8]
                ports_preview = ", ".join(map(str, sample_ports)) + ("..." if len(distinct_ports) > 8 else "")

                print(f"\n{Colors.BG_RED}{Colors.WHITE}{Colors.BOLD} [!] CRITICAL SECURITY ALERT: PORT SCAN DETECTED {Colors.RESET}")
                print(f"{Colors.RED}{Colors.BOLD}[{ts}] SCANNER IP  : {Colors.WHITE}{src_ip}{Colors.RESET}")
                print(f"{Colors.RED}{Colors.BOLD}[{ts}] TARGET IP   : {Colors.YELLOW}{ip.dst}{Colors.RESET}")
                print(f"{Colors.RED}{Colors.BOLD}[{ts}] SYN PROBES  : {Colors.WHITE}{len(distinct_ports)} distinct ports within {self.scan_window}s{Colors.RESET}")
                print(f"{Colors.RED}[{ts}] PORTS TESTED: {Colors.YELLOW}{ports_preview}{Colors.RESET}")
                print(f"{Colors.RED}[{ts}] THREAT      : Reconnaissance / Automated Port Scanner (e.g., Nmap SYN scan){Colors.RESET}")
                print(f"{Colors.RED}{'-' * 65}{Colors.RESET}\n")
                if self.on_alert:
                    self.on_alert("ALERT_SCAN", {
                        "scanner_ip": src_ip,
                        "target_ip": ip.dst,
                        "count": len(distinct_ports),
                        "ports": list(distinct_ports),
                        "timestamp": ts
                    })
                return ("ALERT_SCAN", src_ip, len(distinct_ports))

    # -------------------------------------------------------------
    # Detector 3: Credential Hunter (Unencrypted Protocols)
    # -------------------------------------------------------------
    def process_credentials(self, packet):
        """
        Payload inspection on unencrypted protocols:
        - HTTP: Authorization: Basic header (Base64) & POST form logins
        - FTP: USER / PASS commands (Port 21)
        - Telnet: Cleartext login streams (Port 23)
        """
        if not (packet.haslayer(TCP) and packet.haslayer(Raw)):
            return

        payload = packet[Raw].load
        try:
            # Decode payload text, replace unprintable bytes
            text = payload.decode('latin-1', errors='ignore')
        except Exception:
            return

        src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "Unknown"
        dport = packet[TCP].dport
        sport = packet[TCP].sport
        ts = get_timestamp()

        # 1. HTTP Basic Auth
        if "Authorization: Basic " in text:
            match = re.search(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", text, re.IGNORECASE)
            if match:
                b64_creds = match.group(1).strip()
                try:
                    decoded = base64.b64decode(b64_creds).decode('utf-8', errors='ignore')
                    user, _, passwd = decoded.partition(':')
                    cred_info = {
                        "protocol": "HTTP Basic Auth",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "user": user,
                        "pass": passwd
                    }
                    self.log_credential_alert(ts, cred_info)
                    return ("CREDENTIAL", cred_info)
                except Exception:
                    pass

        # 2. HTTP POST Form Logins (e.g. username=admin&password=secret)
        if "POST " in text and ("password" in text.lower() or "passwd" in text.lower()):
            user_match = re.search(r"(?:username|user|uname|email)=([^&\r\n]+)", text, re.IGNORECASE)
            pass_match = re.search(r"(?:password|passwd|pass)=([^&\r\n]+)", text, re.IGNORECASE)
            if user_match and pass_match:
                cred_info = {
                    "protocol": "HTTP POST Form",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "user": user_match.group(1),
                    "pass": pass_match.group(1)
                }
                self.log_credential_alert(ts, cred_info)
                return ("CREDENTIAL", cred_info)

        # 3. FTP (Port 21): Plaintext USER and PASS commands
        if dport == 21 or sport == 21:
            ftp_user_match = re.search(r"USER\s+([^\r\n]+)", text, re.IGNORECASE)
            if ftp_user_match:
                cred_info = {
                    "protocol": "FTP (Cleartext)",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "user": ftp_user_match.group(1).strip(),
                    "pass": "<Waiting for PASS command>"
                }
                self.log_credential_alert(ts, cred_info)
                return ("CREDENTIAL", cred_info)

            ftp_pass_match = re.search(r"PASS\s+([^\r\n]+)", text, re.IGNORECASE)
            if ftp_pass_match:
                cred_info = {
                    "protocol": "FTP (Cleartext)",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "user": "<Previous USER command>",
                    "pass": ftp_pass_match.group(1).strip()
                }
                self.log_credential_alert(ts, cred_info)
                return ("CREDENTIAL", cred_info)

        # 4. Telnet (Port 23): Plaintext command stream
        if dport == 23 or sport == 23:
            telnet_match = re.search(r"(?:login|user|password):\s*([^\r\n]+)", text, re.IGNORECASE)
            if telnet_match:
                cred_info = {
                    "protocol": "Telnet (Cleartext)",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "user": "Telnet Stream",
                    "pass": telnet_match.group(1).strip()
                }
                self.log_credential_alert(ts, cred_info)
                return ("CREDENTIAL", cred_info)

    def log_credential_alert(self, ts, cred_info):
        self.alert_count += 1
        cred_info["timestamp"] = ts
        self.captured_credentials.append((ts, cred_info))
        print(f"\n{Colors.MAGENTA}{Colors.BOLD}{'=' * 65}{Colors.RESET}")
        print(f"{Colors.MAGENTA}{Colors.BOLD}[*] CREDENTIAL HUNTER: EXPOSED PLAINTEXT CREDENTIAL CAPTURED{Colors.RESET}")
        print(f"{Colors.MAGENTA}[{ts}] PROTOCOL : {Colors.WHITE}{cred_info['protocol']}{Colors.RESET}")
        print(f"{Colors.MAGENTA}[{ts}] SOURCE   : {Colors.YELLOW}{cred_info['src_ip']}{Colors.RESET} -> TARGET: {Colors.YELLOW}{cred_info['dst_ip']}{Colors.RESET}")
        print(f"{Colors.MAGENTA}[{ts}] USERNAME : {Colors.GREEN}{cred_info['user']}{Colors.RESET}")
        print(f"{Colors.MAGENTA}[{ts}] PASSWORD : {Colors.RED}{cred_info['pass']}{Colors.RESET}")
        print(f"{Colors.MAGENTA}{Colors.BOLD}{'=' * 65}{Colors.RESET}\n")
        if self.on_cred:
            self.on_cred(cred_info)

    # -------------------------------------------------------------
    # Main Packet Handler Loop
    # -------------------------------------------------------------
    def packet_callback(self, packet):
        self.packet_count += 1

        # Run through the 3 Anomaly Detectors
        self.process_arp(packet)
        self.process_port_scan(packet)
        self.process_credentials(packet)

        # Periodic status banner every 100 packets
        if self.packet_count % 100 == 0:
            ts = get_timestamp()
            print(
                f"{Colors.GREEN}[{ts}] [STATUS]{Colors.RESET} "
                f"Packets: {self.packet_count} | "
                f"ARP Cached: {len(self.arp_cache)} | "
                f"SYN Tracked: {len(self.syn_tracker)} | "
                f"Alerts: {Colors.RED if self.alert_count else Colors.WHITE}{self.alert_count}{Colors.RESET}"
            )

    def start(self):
        print(f"{Colors.CYAN}{'=' * 65}")
        print(f"  🛡️ CUSTOM CLI NETWORK SNIFFER & ANOMALY DETECTOR (PHASE 1)")
        print(f"{'=' * 65}{Colors.RESET}")
        print(f"{Colors.WHITE}[*] Listening on Interface: {Colors.GREEN}{self.interface}{Colors.RESET}")
        print(f"{Colors.WHITE}[*] Port Scan Trigger     : {Colors.YELLOW}{self.scan_threshold}+ distinct SYNs / {self.scan_window}s{Colors.RESET}")
        print(f"{Colors.WHITE}[*] Credential Inspection : {Colors.YELLOW}HTTP Basic, POST Forms, FTP (21), Telnet (23){Colors.RESET}")
        print(f"{Colors.WHITE}[*] ARP Spoof Detection   : {Colors.YELLOW}Active (In-memory baseline table){Colors.RESET}")
        print(f"{Colors.CYAN}[*] Sniffer running. Press Ctrl+C to stop...{Colors.RESET}\n")

        try:
            sniff(iface=self.interface, prn=self.packet_callback, store=False)
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[*] Sniffer halted by user.{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[-] Sniffing error: {e}{Colors.RESET}")
        finally:
            self.print_summary()

    def print_summary(self):
        print(f"\n{Colors.CYAN}{'=' * 65}")
        print(f"  📋 SESSION SUMMARY REPORT")
        print(f"{'=' * 65}{Colors.RESET}")
        print(f"Total Packets Processed : {self.packet_count}")
        print(f"ARP Packets Inspected   : {self.arp_count}")
        print(f"TCP SYN Probes Analyzed : {self.syn_count}")
        print(f"Cached Device Baselines : {len(self.arp_cache)}")
        print(f"Total Security Alerts   : {Colors.RED if self.alert_count else Colors.GREEN}{self.alert_count}{Colors.RESET}")
        print(f"Credentials Captured    : {len(self.captured_credentials)}")
        print(f"{Colors.CYAN}{'=' * 65}{Colors.RESET}\n")


def parse_args():
    parser = argparse.ArgumentParser(description="Phase 1: Custom CLI Network Sniffer & Anomaly Detector")
    parser.add_argument("-i", "--iface", default=None, help="Network interface to sniff on (default: primary interface)")
    parser.add_argument("--threshold", type=int, default=20, help="Number of distinct ports to flag a port scan (default: 20)")
    parser.add_argument("--window", type=float, default=5.0, help="Sliding window duration in seconds (default: 5.0)")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    sniffer = AnomalySnifferCLI(
        interface=args.iface,
        scan_threshold=args.threshold,
        scan_window=args.window
    )
    sniffer.start()
