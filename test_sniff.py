from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

print("[*] Sniffing for 3 packets (timeout 10s)... (browse a website if traffic is slow)")
sniff(prn=packet_callback, count=3, timeout=10)
print("[+] Environment verified successfully!")
