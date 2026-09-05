#!/usr/bin/env python3
"""
Lateral Movement & Ransomware Vector Detection Engine
Analyzes network connection logs for SMB port 445 abuse and rapid sweeps.
Mapped to MITRE ATT&CK: T1021.002 (SMB Shares) & T1046 (Network Service Discovery)
"""

from collections import defaultdict
import re

LOG_FILE = "data/incident.log"
SUSPICIOUS_PORT = "445"
VOLUME_THRESHOLD = 10
CRITICAL_ASSETS = {
    "192.168.56.20": "FILE01 (Primary Enterprise File Server)"
}

def analyze_traffic(file_path):
    print("=" * 65)
    print("🛡️  APEX MANUFACTURING SOC: AUTOMATED DETECTION ENGINE")
    print("=" * 65)
    
    activity = defaultdict(lambda: defaultdict(int))
    log_pattern = re.compile(r'(\d{2}:\d{2}:\d{2})\s+(\d+\.\d+\.\d+\.\d+)\s+->\s+(\d+\.\d+\.\d+\.\d+):(\d+)')
    
    try:
        with open(file_path, 'r') as f:
            for line in f:
                match = log_pattern.search(line.strip())
                if match:
                    _, src_ip, dst_ip, port = match.groups()
                    if port == SUSPICIOUS_PORT:
                        activity[src_ip][dst_ip] += 1
    except FileNotFoundError:
        print(f"[-] Error: Target log file not found at {file_path}")
        return

    for src, targets in activity.items():
        total_attempts = sum(targets.values())
        unique_targets = len(targets)
        hit_critical_asset = any(dst in CRITICAL_ASSETS for dst in targets)
        
        print(f"\n[+] Monitored Source Host: {src} (SOC01 Workstation)")
        print(f"    Total Port {SUSPICIOUS_PORT} (SMB) Requests : {total_attempts}")
        print(f"    Unique Internal Targets Probed: {unique_targets}")
        
        for dst, count in targets.items():
            asset_label = f" [{CRITICAL_ASSETS[dst]}]" if dst in CRITICAL_ASSETS else ""
            print(f"      -> Target {dst}{asset_label}: {count} requests")

        # Determine Alert Severity
        if hit_critical_asset and total_attempts >= VOLUME_THRESHOLD:
            severity = "CRITICAL"
        elif unique_targets > 1 or total_attempts >= VOLUME_THRESHOLD:
            severity = "HIGH"
        else:
            severity = "INFORMATIONAL"

        if severity in ["CRITICAL", "HIGH"]:
            print("\n" + "!" * 65)
            print(f"🚨 [ALERT: {severity} SEVERITY] LATERAL MOVEMENT DETECTED")
            print("!" * 65)
            print("▶ MITRE ATT&CK Techniques:")
            print("   • T1021.002 - Remote Services: SMB/Windows Admin Shares")
            print("   • T1046     - Network Service Discovery (Port Scan / Sweep)")
            print(f"▶ Recommended Action: Immediately quarantine {src} from subnet 192.168.56.0/24.")
            print("!" * 65)

    print("\n" + "=" * 65)

if __name__ == "__main__":
    analyze_traffic(LOG_FILE)
