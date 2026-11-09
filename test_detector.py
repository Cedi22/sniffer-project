from scapy.all import ARP

# 1. Import your cache and processing function from your detector script
from arp_detector import arp_cache, process_arp_packet

print("[*] Running verification test...\n")

# Step A: Feed the function a legitimate baseline packet
# Simulate a packet from router 192.168.1.1 with MAC 11:11:11:11:11:11
legit_packet = ARP(op=2, psrc="192.168.1.1", hwsrc="11:11:11:11:11:11")
print("[1] Feeding legitimate ARP reply...")
process_arp_packet(legit_packet)

# Step B: Feed the function a conflicting packet
# Same IP (192.168.1.1), but a totally different MAC (99:99:99:99:99:99)
spoofed_packet = ARP(op=2, psrc="192.168.1.1", hwsrc="99:99:99:99:99:99")
print("\n[2] Feeding conflicting ARP reply (same IP, different MAC)...")
process_arp_packet(spoofed_packet)