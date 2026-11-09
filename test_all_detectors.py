"""
Automated Verification Suite for All Phase 1 Detectors
------------------------------------------------------
Simulates:
1. ARP Spoofing Conflict
2. TCP Port Scan (25 distinct SYN requests in <1 second)
3. Credential Interception (HTTP Basic Auth, POST Form, FTP USER/PASS)
"""

import sys
import os
import base64
from scapy.all import ARP, IP, TCP, Raw

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from cli_detector import AnomalySnifferCLI, Colors

def run_tests():
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 65}")
    print("  RUNNING PHASE 1 COMPREHENSIVE DETECTOR VERIFICATION SUITE")
    print(f"{'=' * 65}{Colors.RESET}\n")

    detector = AnomalySnifferCLI(scan_threshold=20, scan_window=5.0)

    # -------------------------------------------------------------
    # TEST 1: ARP Spoof Detector
    # -------------------------------------------------------------
    print(f"{Colors.BOLD}{Colors.WHITE}--> [TEST 1] Testing ARP Spoof Detector...{Colors.RESET}")
    # Legitimate packet: 192.168.1.1 -> 11:11:11:11:11:11
    pkt_legit = ARP(op=2, psrc="192.168.1.1", hwsrc="11:11:11:11:11:11")
    res1 = detector.process_arp(pkt_legit)
    assert res1[0] == "LEARN_ARP", f"Failed learning ARP baseline: {res1}"

    # Conflicting packet: same IP, different MAC
    pkt_spoof = ARP(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff")
    res2 = detector.process_arp(pkt_spoof)
    assert res2[0] == "ALERT_ARP", f"Failed to alert on ARP conflict: {res2}"
    print(f"{Colors.GREEN}[✓] TEST 1 PASSED: ARP Spoofing correctly flagged!{Colors.RESET}\n")

    # -------------------------------------------------------------
    # TEST 2: Port Scan Detector (SYN Sliding Window)
    # -------------------------------------------------------------
    print(f"{Colors.BOLD}{Colors.WHITE}--> [TEST 2] Testing Port Scan Detector (25 SYN probes)...{Colors.RESET}")
    attacker_ip = "10.0.0.150"
    target_ip = "192.168.1.1"

    scan_detected = False
    for port in range(1, 26):  # 25 distinct destination ports (threshold is 20)
        # TCP flags=0x02 is SYN
        syn_pkt = IP(src=attacker_ip, dst=target_ip) / TCP(sport=50000 + port, dport=port, flags="S")
        res = detector.process_port_scan(syn_pkt)
        if res and res[0] == "ALERT_SCAN":
            scan_detected = True

    assert scan_detected, "Failed to detect SYN port scan over threshold!"
    print(f"{Colors.GREEN}[✓] TEST 2 PASSED: Port scan exceeding 20 ports in 5s correctly flagged!{Colors.RESET}\n")

    # -------------------------------------------------------------
    # TEST 3: Credential Hunter (HTTP Basic, POST Form, FTP)
    # -------------------------------------------------------------
    print(f"{Colors.BOLD}{Colors.WHITE}--> [TEST 3] Testing Credential Hunter...{Colors.RESET}")

    # A. HTTP Basic Auth
    # 'admin:SecretPass123' encoded in base64: 'YWRtaW46U2VjcmV0UGFzczEyMw=='
    b64_creds = base64.b64encode(b"admin:SecretPass123").decode()
    http_payload = (
        f"GET /admin HTTP/1.1\r\n"
        f"Host: 192.168.1.1\r\n"
        f"Authorization: Basic {b64_creds}\r\n\r\n"
    ).encode()
    http_pkt = IP(src="192.168.1.50", dst="192.168.1.1") / TCP(sport=43210, dport=80) / Raw(load=http_payload)
    res_http = detector.process_credentials(http_pkt)
    assert res_http and res_http[0] == "CREDENTIAL"
    assert res_http[1]["user"] == "admin" and res_http[1]["pass"] == "SecretPass123"

    # B. HTTP POST Form
    post_payload = (
        "POST /login HTTP/1.1\r\n"
        "Host: testportal.local\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
        "username=alice&password=SuperSecretPassword99!"
    ).encode()
    post_pkt = IP(src="192.168.1.75", dst="192.168.1.200") / TCP(sport=43211, dport=8080) / Raw(load=post_payload)
    res_post = detector.process_credentials(post_pkt)
    assert res_post and res_post[0] == "CREDENTIAL"
    assert res_post[1]["user"] == "alice" and res_post[1]["pass"] == "SuperSecretPassword99!"

    # C. FTP Plaintext
    ftp_user_pkt = IP(src="192.168.1.80", dst="192.168.1.10") / TCP(sport=43212, dport=21) / Raw(load=b"USER ftp_admin\r\n")
    res_ftp_user = detector.process_credentials(ftp_user_pkt)
    assert res_ftp_user and res_ftp_user[0] == "CREDENTIAL"
    assert res_ftp_user[1]["user"] == "ftp_admin"

    ftp_pass_pkt = IP(src="192.168.1.80", dst="192.168.1.10") / TCP(sport=43212, dport=21) / Raw(load=b"PASS hunter2\r\n")
    res_ftp_pass = detector.process_credentials(ftp_pass_pkt)
    assert res_ftp_pass and res_ftp_pass[0] == "CREDENTIAL"
    assert res_ftp_pass[1]["pass"] == "hunter2"

    print(f"{Colors.GREEN}[✓] TEST 3 PASSED: Intercepted HTTP Basic Auth, POST forms, and FTP credentials!{Colors.RESET}\n")

    # Print final summary
    detector.print_summary()
    print(f"{Colors.BOLD}{Colors.GREEN}[SUCCESS] All Phase 1 Anomaly Detectors verified and operational!{Colors.RESET}\n")


if __name__ == "__main__":
    run_tests()

