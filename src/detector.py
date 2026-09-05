#!/usr/bin/env python3
"""
Ransomware Lateral Movement Detector
Analyzes network connection logs for SMB port 445 scanning/sweeping activity.
"""

from collections import defaultdict
import re

LOG_FILE = "data/incident.log"
SUSPICIOUS_PORT = "445"
THRESHOLD_CONNECTIONS = 3

def analyze_log(file_path):
    print("=" * 60)
    print("🔍 INITIATING SOC LOG ANALYSIS: RANSOMWARE DETECTION")
    print("=" * 60)
    
    # Track connection counts: source_ip -> {destination_ip: count}
    activity = defaultdict(lambda: defaultdict(int))
    
    # Regular expression to extract: timestamp, source_ip, dest_ip, port
    log_pattern = re.compile(r'(\d{2}:\d{2}:\d{2})\s+(\d+\.\d+\.\d+\.\d+)\s+->\s+(\d+\.\d+\.\d+\.\d+):(\d+)')
    
    try:
        with open(file_path, 'r') as f:
            for line in f:
                match = log_pattern.search(line.strip())
                if match:
                    timestamp, src_ip, dst_ip, port = match.groups()
                    if port == SUSPICIOUS_PORT:
                        activity[src_ip][dst_ip] += 1
                        
    except FileNotFoundError:
        print(f"[-] Error: Could not find log file at {file_path}")
        return

    # Detection Evaluation
    alerts_triggered = False
    for src, targets in activity.items():
        total_smb_attempts = sum(targets.values())
        unique_targets = len(targets)
        
        print(f"\n[+] Source IP: {src}")
        print(f"    Total Port {SUSPICIOUS_PORT} (SMB) Connections: {total_smb_attempts}")
        print(f"    Unique Internal Targets Probed: {unique_targets}")
        
        for dst, count in targets.items():
            print(f"      -> Target {dst}: {count} connection requests")

        # Flag rule: Multiple attempts across multiple internal targets
        if unique_targets > 1 or total_smb_attempts >= THRESHOLD_CONNECTIONS:
            alerts_triggered = True
            print("\n🚨 [ALERT: HIGH SEVERITY] Potential Ransomware Lateral Movement Detected!")
            print(f"   Action: Isolate host {src} immediately to contain lateral spread.")
            
    if not alerts_triggered:
        print("\n[✓] No anomalous SMB lateral movement detected.")
        
    print("=" * 60)

if __name__ == "__main__":
    analyze_log(LOG_FILE)
