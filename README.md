Lateral Movement & Ransomware Vector Detection (SOC Portfolio Lab)
📌 Executive Summary
This project demonstrates end-to-end detection, deep packet inspection (DPI), and containment of simulated internal lateral movement targeting Server Message Block (SMB / TCP 445) within an enterprise environment (Apex Manufacturing Ltd.).

Using an isolated dual-VM virtual network, network telemetry was captured, analyzed with Wireshark/TShark, and processed through a custom Python detection script mapped directly to MITRE ATT&CK techniques.

🏗️ Architecture & Lab Setup
Compromised Host / Attacker (SOC01): 192.168.56.101 (Kali Linux)

Target Enterprise File Server (FILE01): 192.168.56.20 (Kali Linux)

Subnet: 192.168.56.0/24 (VirtualBox Host-Only Isolated Network)

🔍 Investigation & Traffic Analysis
1. Baseline Network Telemetry
Normal host-to-host communication was established via ICMP Echo Requests (pcaps/baseline.pcap), validating standard point-to-point traffic, ARP resolution, and 0% packet loss.

2. Attack Simulation & Anomaly Breakdown
A suspicious surge of TCP port 445 connection attempts was directed from the compromised workstation to the primary enterprise file server:

Rate: 20 connection requests generated in < 0.1 seconds.

Wireshark / DPI Analysis: Captured 44 frames containing rapid asymmetric SYN floods and TCP resets (RST, ACK), matching automated ransomware enumeration patterns.

🛡️ Automated Detection Engine
The custom Python detection engine (src/pcap_detector.py) performs deep packet inspection across raw PCAP files to flag unauthorized reconnaissance and lateral movement:

Volume Threshold: Triggers on high-frequency connection bursts (>= 10 SYN probes).

Critical Asset Tagging: Automatically elevates alert severity when high-value infrastructure (FILE01) is targeted.

MITRE ATT&CK Mapping:

T1046 — Network Service Discovery

T1021.002 — Remote Services: SMB/Windows Admin Shares

Detection Engine Verification Output
=================================================================
📡 NETWORK TRAFFIC ANALYSIS: PCAP DEEP PACKET INSPECTION
[*] Ingested 44 total network frames from pcaps/ransomware-simulation.pcap

[+] Flagged Traffic Origin: 192.168.56.101
Target Service        : TCP/445 (SMB)
Total SYN Probes Sent : 20
-> Probed Destination: 192.168.56.20 [FILE01 (Primary Enterprise File Server)] (20 SYN packets)

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
🚨 [NTA ALERT] RAPID SMB SYN SCAN / LATERAL MOVEMENT DETECTED
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
▶ Threat Signature : High-frequency TCP/445 connection burst
▶ MITRE Technique  : T1046 (Network Service Discovery)
▶ MITRE Technique  : T1021.002 (SMB/Windows Admin Shares)
▶ Impact Assessment: High-value asset targeted (FILE01)
▶ Recommended Action: Deploy host firewall block rule against 192.168.56.101.
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

🔒 Containment & Defensive Remediation
Network Segmentation & ACLs: Implement router/switch access-lists (ACLs) to strictly isolate user workstation subnets from direct access to admin-level SMB shares.

Endpoint Hardening: Enforce host firewall policies blocking inbound TCP/445 across non-server endpoints.

Identity & Access Governance: Enforce SMB signing, deprecate SMBv1 across the enterprise, and restrict privileged administrative accounts from logging into general user endpoints.
