# Network Packet Analyser

A Python tool that captures and analyses live network traffic, displaying
source/destination IPs, protocols, ports, and services — then produces a
structured summary of traffic patterns and exports results to CSV.

Built to demonstrate hands-on understanding of network traffic fundamentals:
the same knowledge used when diagnosing connectivity issues in enterprise
IT environments.

---

## What it does

| Feature | Description |
|---|---|
| Live capture | Captures packets in real time on any network interface |
| Protocol detection | Identifies TCP, UDP, ICMP, ARP, DNS traffic |
| Service mapping | Maps destination ports to services (HTTP, HTTPS, SSH, RDP, DNS, SMB, etc.) |
| TCP flag parsing | Extracts SYN, ACK, FIN, RST, PSH flags |
| DNS inspection | Extracts DNS query names from UDP packets |
| Traffic summary | Protocol breakdown, top IPs, top services, conversation pairs |
| CSV export | Saves packet log and summary for offline analysis |
| Demo mode | Runs with synthetic data if no sudo access available |

---

## Sample output

```
Network Packet Analyser
========================================
Capturing 100 packets...

  PROTO  SRC IP               →  DST IP               SIZE    INFO
  ----------------------------------------------------------------
  TCP    192.168.1.10         →  142.250.180.46        1420B  54231 → 443 [HTTPS][ACK]
  UDP    192.168.1.10         →  8.8.8.8                 73B  DNS Query: www.google.com.
  TCP    192.168.1.10         →  151.101.1.140           60B  54232 → 443 [HTTPS][SYN]
  ICMP   192.168.1.10         →  1.1.1.1                 84B  Echo Request
  TCP    142.250.180.46       →  192.168.1.10           890B  443 → 54231 [HTTPS][ACK+PSH]

=================================================================
  NETWORK TRAFFIC ANALYSIS SUMMARY
=================================================================
  Total packets captured:  100
  Total data:              87,432 bytes (85.4 KB)
  Average packet size:     874.3 bytes

  ── Protocol breakdown ──────────────────────────
  TCP      72 packets ( 72.0%)  ████████████████████████  64,821B
  UDP      18 packets ( 18.0%)  ██████                    12,304B
  ICMP      8 packets (  8.0%)  ██                         5,120B
  ARP       2 packets (  2.0%)  █                          1,187B

  ── Top services detected ───────────────────────
  HTTPS           58 packets
  DNS             18 packets
  HTTP             9 packets
  SSH              4 packets
  ICMP Echo        8 packets
```

---

## How to run

**Install dependency:**
```bash
pip install scapy
```

**Capture 100 packets (requires sudo on Linux/Mac):**
```bash
sudo python analyser.py
```

**Filter by protocol:**
```bash
sudo python analyser.py --filter tcp
sudo python analyser.py --filter "port 443"
sudo python analyser.py --filter udp
```

**Capture more packets:**
```bash
sudo python analyser.py --count 500
```

**Run demo mode (no sudo needed):**
```bash
python analyser.py --demo
```

**On Windows:** Run Command Prompt as Administrator, then:
```bash
python analyser.py
```

---

## Output files

All outputs saved to `/output`:

| File | Description |
|---|---|
| `packets_YYYY-MM-DD_HH-MM-SS.csv` | Full packet log — one row per packet |
| `summary_YYYY-MM-DD_HH-MM-SS.csv` | Traffic summary — protocol counts, top IPs, services |

---

## Skills demonstrated

- **Network protocols:** TCP/IP, UDP, ICMP, ARP, DNS — understanding of how
  packets traverse a network, what flags indicate, and how services map to ports
- **Enterprise services:** Recognition of RDP (3389), SMB (445), WinRM (5985),
  SSH (22) — the ports an IT support engineer encounters daily
- **Traffic analysis:** Identifying top talkers, unusual traffic patterns,
  and protocol distribution — foundational for network troubleshooting
- **Python:** Packet processing, data aggregation, CSV export

---

## Why network packet analysis matters in IT infrastructure

When a user reports "the internet is slow" or "I can't reach the file server,"
a network packet capture is one of the first diagnostic steps. Understanding
what you see in a capture — whether a TCP handshake completed, whether DNS
resolved correctly, whether packets are being dropped — is a core skill for
any IT infrastructure engineer.

This tool replicates that workflow in code.

---

## Dependencies

```
scapy>=2.5.0
```

---

## Author

Atrija Haldar
[LinkedIn](https://www.linkedin.com/in/atrija-haldar-196a3b221/)
MSc Engineering, Technology and Business Management — University of Leeds
