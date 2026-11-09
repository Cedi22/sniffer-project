import sys
from datetime import datetime

try:
    from scapy.all import sniff, ARP, conf
except Exception as e:
    print(f"[-] Error loading Scapy: {e}")
    sys.exit(1)

arp_cache = {}

def process_arp_packet(packet, alert_callback=None, learn_callback=None):
    """
    Process an incoming packet. If it's an ARP reply (op=2),
    check if IP is already in cache with a different MAC (spoofing).
    """
    if packet.haslayer(ARP):
        arp_layer = packet[ARP]
        if arp_layer.op == 2:  # is-at / ARP reply
            src_ip = arp_layer.psrc
            src_mac = arp_layer.hwsrc.lower()

            if src_ip in arp_cache:
                known_mac = arp_cache[src_ip].lower()
                if known_mac != src_mac:
                    alert_info = {
                        "timestamp": datetime.now().strftime("%H:%M:%S"),
                        "ip": src_ip,
                        "original_mac": known_mac,
                        "attacker_mac": src_mac,
                    }
                    print("\n" + "!" * 50)
                    print(f"[!] ALERT: Possible ARP Spoofing Detected!")
                    print(f"[!] Target IP   : {src_ip}")
                    print(f"[!] Original MAC: {known_mac}")
                    print(f"[!] Attacker MAC: {src_mac}")
                    print("!" * 50 + "\n")
                    if alert_callback:
                        alert_callback(alert_info)
                    return ("ALERT", alert_info)
            else:
                arp_cache[src_ip] = src_mac
                event_info = {
                    "timestamp": datetime.now().strftime("%H:%M:%S"),
                    "ip": src_ip,
                    "mac": src_mac,
                }
                print(f"[*] Learned mapping: {src_ip} -> {src_mac}")
                if learn_callback:
                    learn_callback(event_info)
                return ("LEARNED", event_info)
    return (None, None)

def start_sniffing(interface=None, stop_filter=None, prn=None):
    if interface:
        conf.iface = interface
    target_prn = prn if prn else process_arp_packet
    sniff(filter="arp", store=False, prn=target_prn, stop_filter=stop_filter)

if __name__ == "__main__":
    print("[*] Script started. Scapy loaded.")
    print(f"[*] Default interface: {conf.iface}")
    print("[*] Starting ARP sniffing loop. Press Ctrl+C to stop...")
    try:
        sniff(filter="arp", store=False, prn=process_arp_packet)
    except KeyboardInterrupt:
        print("\n[*] Stopped sniffing.")
    except Exception as e:
        print(f"[-] Sniffing error: {e}")
