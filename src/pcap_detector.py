#!/usr/bin/env python3
"""
Deep Packet Inspection (DPI) & SMB Sweep Analyzer
Reads raw network capture files (.pcap) using Scapy to detect TCP SYN floods and lateral movement.
"""

import sys
from collections import defaultdict
from scapy.all import rdpcap, TCP, IP

PCAP_FILE = "data/attack.pcap"
SMB_PORT = 445
SYN_THRESHOLD = 10
CRITICAL_HOSTS = {
    "192.168.56.20": "FILE01 (Primary Enterprise File Server)"
}

def analyze_pcap(file_path):
    print("=" * 65)
    print("📡 NETWORK TRAFFIC ANALYSIS: PCAP DEEP PACKET INSPECTION")
    print("=" * 65)
    
    try:
        packets = rdpcap(file_path)
    except FileNotFoundError:
        print(f"[-] Error: Could not locate PCAP file at {file_path}")
        return
    except Exception as e:
        print(f"[-] Error reading PCAP: {e}")
        return

    print(f"[*] Ingested {len(packets)} total network frames from {file_path}")
    
    # Track metrics: (src_ip, dst_ip) -> count of SYN packets
    syn_counts = defaultdict(lambda: defaultdict(int))
    rst_ack_counts = defaultdict(lambda: defaultdict(int))
    
    for pkt in packets:
        if IP in pkt and TCP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            dport = pkt[TCP].dport
            flags = pkt[TCP].flags
            
            # Check for SMB target port (445)
            if dport == SMB_PORT:
                # Flag 'S' = SYN packet (connection initiation)
                if flags == "S" or flags == 0x02:
                    syn_counts[src][dst] += 1
            
            # Flag 'RA' = RST, ACK (connection rejected/reset by target)
            if flags == "RA" or flags == 0x14:
                rst_ack_counts[src][dst] += 1

    # Evaluate Detections
    for src, targets in syn_counts.items():
        total_syns = sum(targets.values())
        print(f"\n[+] Flagged Traffic Origin: {src}")
        print(f"    Target Service        : TCP/445 (SMB)")
        print(f"    Total SYN Probes Sent : {total_syns}")
        
        for dst, count in targets.items():
            asset_info = f" [{CRITICAL_HOSTS[dst]}]" if dst in CRITICAL_HOSTS else ""
            print(f"      -> Probed Destination: {dst}{asset_info} ({count} SYN packets)")
        
        # Alert Threshold Check
        if total_syns >= SYN_THRESHOLD:
            print("\n" + "!" * 65)
            print("🚨 [NTA ALERT] RAPID SMB SYN SCAN / LATERAL MOVEMENT DETECTED")
            print("!" * 65)
            print("▶ Threat Signature : High-frequency TCP/445 connection burst")
            print("▶ MITRE Technique  : T1046 (Network Service Discovery)")
            print("▶ MITRE Technique  : T1021.002 (SMB/Windows Admin Shares)")
            if any(dst in CRITICAL_HOSTS for dst in targets):
                print("▶ Impact Assessment: High-value asset targeted (FILE01)")
            print(f"▶ Recommended Action: Deploy host firewall block rule against {src}.")
            print("!" * 65)

    print("\n" + "=" * 65)

if __name__ == "__main__":
    pcap_path = sys.argv[1] if len(sys.argv) > 1 else PCAP_FILE
    analyze_pcap(pcap_path)
