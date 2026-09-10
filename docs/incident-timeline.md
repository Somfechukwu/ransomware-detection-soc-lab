# Incident Timeline & Triage Report: Apex Manufacturing Ltd.

## 1. Incident Overview

* **Incident ID:** INC-2026-0914-01
* **Severity Level:** CRITICAL
* **Suspected Activity:** Internal Reconnaissance / Lateral Movement (Simulated Ransomware Vector)
* **Impacted Systems:**
  * **Source / Compromised Workstation:** `192.168.56.101` (`SOC01` - Kali Linux)
  * **Destination Target:** `192.168.56.20` (`FILE01` - Primary Enterprise File Server)
  * **Network Segment:** `192.168.56.0/24` (Isolated Manufacturing VNet)

---

## 2. Event Timeline & Telemetry Correlation

| Timestamp (UTC) | Source IP | Destination IP:Port | Protocol | Event & Telemetry Breakdown |
| :--- | :--- | :--- | :--- | :--- |
| **09:14:00 - 09:14:02** | `192.168.56.101` | `192.168.56.20` | ICMP | Baseline connectivity verified (Echo request/reply, 0% packet loss). |
| **09:14:08.100** | `192.168.56.101` | `192.168.56.20:445` | TCP/SMB | Initial high-frequency TCP `SYN` flood initiated against SMB service. |
| **09:14:08.195** | `192.168.56.101` | `192.168.56.20:445` | TCP/SMB | Burst completed: **20 SYN probes generated in < 0.1s**; 44 total frames recorded with asymmetric `RST, ACK` returns. |
| **09:14:08.210** | Detection Engine | `192.168.56.101` | Alert | `[NTA ALERT]` triggered via `src/pcap_detector.py`: Threshold exceeded (>=10 SYN probes) and critical asset (`FILE01`) tagged. |

---

## 3. Threat Assessment & Technical Findings

The observed telemetry indicates automated discovery and lateral movement staging against internal file-sharing services (TCP 445):

* **MITRE ATT&CK Mapping:**
  * **T1046:** Network Service Discovery
  * **T1021.002:** Remote Services: SMB/Windows Admin Shares
* **DPI Observation:** The sub-second transmission rate of TCP `SYN` frames without completion of full 3-way handshakes confirms automated scanning tool behavior rather than organic user interaction.
* **Risk Evaluation:** High likelihood of precursor activity to unauthorized network share mounting, staging, or automated ransomware distribution.

---

## 4. Immediate Containment & Defensive Playbook

### Step 1: Network-Level Quarantine
Deploy an immediate access-control block on the distribution/access switch to isolate the compromised endpoint:

```text
! Cisco Switch Port Access-List Isolation
ip access-list extended BLOCK_LATERAL_SOC01
 10 deny ip host 192.168.56.101 host 192.168.56.20
 20 deny tcp host 192.168.56.101 any eq 445
 30 permit ip any any
```

### Step 2: Host Firewall Enforcement (FILE01)
Drop all inbound traffic originating from the flagged IP at the server kernel level:

```bash
# Apply host-level isolation rule on FILE01
sudo iptables -A INPUT -s 192.168.56.101 -p tcp --dport 445 -j DROP
```

### Step 3: Identity & Endpoint Forensics
1. Invalidate active Kerberos tickets and force session revocation for accounts logged into `SOC01`.
2. Inspect volatile memory and process trees on `192.168.56.101` for anomalous outbound socket creation.
3. Review audit logs on `FILE01` (`/var/log/samba/` or Windows Event IDs `4624` / `4625`) for unauthorized SMB session negotiation.
