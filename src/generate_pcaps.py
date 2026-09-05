#!/usr/bin/env python3
"""
Generate baseline and attack PCAP captures to simulate SOC network telemetry.
"""
from scapy.all import IP, TCP, ICMP, Ether, wrpcap
import time

def create_baseline():
    packets = []
    # 10 ICMP Ping requests and replies between SOC01 and FILE01
    for _ in range(5):
        # Echo Request
        packets.append(Ether()/IP(src="192.168.56.10", dst="192.168.56.20")/ICMP(type=8))
        # Echo Reply
        packets.append(Ether()/IP(src="192.168.56.20", dst="192.168.56.10")/ICMP(type=0))
    
    wrpcap("data/baseline.pcap", packets)
    print(f"[✓] Created data/baseline.pcap ({len(packets)} frames)")

def create_attack():
    packets = []
    # 22 SYN requests from SOC01 + 22 RST,ACK replies from FILE01 = 44 frames total
    sport = 49152
    for _ in range(22):
        # SYN from workstation
        syn_pkt = Ether()/IP(src="192.168.56.10", dst="192.168.56.20")/TCP(sport=sport, dport=445, flags="S", seq=1000)
        packets.append(syn_pkt)
        
        # RST, ACK response from server
        rst_pkt = Ether()/IP(src="192.168.56.20", dst="192.168.56.10")/TCP(sport=445, dport=sport, flags="RA", seq=0, ack=1001)
        packets.append(rst_pkt)
        sport += 1
        
    wrpcap("data/attack.pcap", packets)
    print(f"[✓] Created data/attack.pcap ({len(packets)} frames)")

if __name__ == "__main__":
    create_baseline()
    create_attack()
