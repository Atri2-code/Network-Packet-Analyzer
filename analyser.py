"""
Network Packet Analyser
========================
Captures and analyses live network traffic on your machine.
Displays source/destination IPs, protocols, packet sizes,
and logs results to CSV for analysis.

Demonstrates hands-on understanding of network traffic fundamentals —
the same knowledge used when diagnosing connectivity issues in
enterprise IT environments.

Usage:
  sudo python analyser.py              # Capture 100 packets (default)
  sudo python analyser.py --count 500  # Capture 500 packets
  sudo python analyser.py --filter tcp # Filter by protocol
  sudo python analyser.py --summary    # Show summary only

Note: Requires sudo/admin privileges for packet capture.

Author: Atrija Haldar
"""

import argparse
import csv
import os
from collections import Counter, defaultdict
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("  scapy not installed. Run: pip install scapy")
    print("  Running in demo mode with synthetic data.\n")

OUTPUT_DIR = "output"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── Packet store ───────────────────────────────────────────────────────────────

captured_packets = []


# ── Protocol mapping ───────────────────────────────────────────────────────────

PROTOCOL_MAP = {
    1:  "ICMP",
    6:  "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    89: "OSPF",
}

WELL_KNOWN_PORTS = {
    20:   "FTP-data",
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    67:   "DHCP",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3389: "RDP",
    5985: "WinRM",
    8080: "HTTP-alt",
}


def get_protocol_name(proto_num: int) -> str:
    return PROTOCOL_MAP.get(proto_num, f"Proto-{proto_num}")


def get_service(port: int) -> str:
    return WELL_KNOWN_PORTS.get(port, str(port))


# ── Packet processing ──────────────────────────────────────────────────────────

def process_packet(packet) -> dict:
    """
    Extracts fields from a captured packet.
    Returns a structured dict for logging and analysis.
    """
    record = {
        "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
        "src_ip":      "",
        "dst_ip":      "",
        "protocol":    "Unknown",
        "src_port":    "",
        "dst_port":    "",
        "service":     "",
        "size_bytes":  len(packet),
        "flags":       "",
        "info":        "",
    }

    if packet.haslayer(IP):
        ip = packet[IP]
        record["src_ip"]   = ip.src
        record["dst_ip"]   = ip.dst
        record["protocol"] = get_protocol_name(ip.proto)

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            record["src_port"] = tcp.sport
            record["dst_port"] = tcp.dport
            record["service"]  = get_service(tcp.dport)

            # Parse TCP flags
            flags = []
            if tcp.flags & 0x01: flags.append("FIN")
            if tcp.flags & 0x02: flags.append("SYN")
            if tcp.flags & 0x04: flags.append("RST")
            if tcp.flags & 0x08: flags.append("PSH")
            if tcp.flags & 0x10: flags.append("ACK")
            if tcp.flags & 0x20: flags.append("URG")
            record["flags"] = "+".join(flags) if flags else ""
            record["info"]  = f"{tcp.sport} → {tcp.dport} [{record['flags']}]"

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            record["src_port"] = udp.sport
            record["dst_port"] = udp.dport
            record["service"]  = get_service(udp.dport)
            record["info"]     = f"{udp.sport} → {udp.dport}"

            if packet.haslayer(DNS):
                dns = packet[DNS]
                if dns.qd:
                    record["info"] = f"DNS Query: {dns.qd.qname.decode()}"

        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            icmp_types = {0: "Echo Reply", 3: "Dest Unreachable",
                          8: "Echo Request", 11: "Time Exceeded"}
            record["info"] = icmp_types.get(icmp.type, f"Type {icmp.type}")

    elif packet.haslayer(ARP):
        arp = packet[ARP]
        record["protocol"] = "ARP"
        record["src_ip"]   = arp.psrc
        record["dst_ip"]   = arp.pdst
        record["info"]     = f"Who has {arp.pdst}? Tell {arp.psrc}"

    return record


def packet_callback(packet):
    """Called for each captured packet."""
    record = process_packet(packet)
    captured_packets.append(record)

    # Live display
    proto  = record["protocol"].ljust(6)
    src    = record["src_ip"].ljust(18)
    dst    = record["dst_ip"].ljust(18)
    size   = str(record["size_bytes"]).rjust(6)
    info   = record["info"][:40] if record["info"] else record["service"]

    print(f"  {proto} {src} → {dst} {size}B  {info}")


# ── Analysis ───────────────────────────────────────────────────────────────────

def analyse_traffic(packets: list) -> dict:
    """
    Computes summary statistics from captured packets.
    """
    if not packets:
        return {}

    total_bytes    = sum(p["size_bytes"] for p in packets)
    proto_counts   = Counter(p["protocol"] for p in packets)
    src_ip_counts  = Counter(p["src_ip"] for p in packets if p["src_ip"])
    dst_ip_counts  = Counter(p["dst_ip"] for p in packets if p["dst_ip"])
    service_counts = Counter(p["service"] for p in packets if p["service"])

    # Conversation pairs (src → dst)
    conversations  = Counter(
        f"{p['src_ip']} → {p['dst_ip']}"
        for p in packets if p["src_ip"] and p["dst_ip"]
    )

    # Traffic by protocol in bytes
    proto_bytes = defaultdict(int)
    for p in packets:
        proto_bytes[p["protocol"]] += p["size_bytes"]

    return {
        "total_packets":    len(packets),
        "total_bytes":      total_bytes,
        "avg_packet_size":  round(total_bytes / len(packets), 1),
        "proto_counts":     proto_counts,
        "proto_bytes":      dict(proto_bytes),
        "top_src_ips":      src_ip_counts.most_common(10),
        "top_dst_ips":      dst_ip_counts.most_common(10),
        "top_services":     service_counts.most_common(10),
        "top_conversations":conversations.most_common(10),
    }


def print_summary(analysis: dict):
    """Prints a formatted traffic summary to console."""
    if not analysis:
        return

    print("\n" + "=" * 65)
    print("  NETWORK TRAFFIC ANALYSIS SUMMARY")
    print("=" * 65)
    print(f"  Total packets captured:  {analysis['total_packets']}")
    print(f"  Total data:              {analysis['total_bytes']:,} bytes "
          f"({analysis['total_bytes']/1024:.1f} KB)")
    print(f"  Average packet size:     {analysis['avg_packet_size']} bytes")

    print(f"\n  ── Protocol breakdown ──────────────────────────")
    for proto, count in analysis["proto_counts"].most_common():
        pct   = count / analysis["total_packets"] * 100
        bytes_ = analysis["proto_bytes"].get(proto, 0)
        bar   = "█" * int(pct / 3)
        print(f"  {proto.ljust(8)} {str(count).rjust(5)} packets "
              f"({pct:5.1f}%)  {bar}  {bytes_:,}B")

    print(f"\n  ── Top 5 source IPs ────────────────────────────")
    for ip, count in analysis["top_src_ips"][:5]:
        print(f"  {ip.ljust(20)} {count} packets")

    print(f"\n  ── Top 5 destination IPs ───────────────────────")
    for ip, count in analysis["top_dst_ips"][:5]:
        print(f"  {ip.ljust(20)} {count} packets")

    print(f"\n  ── Top services detected ───────────────────────")
    for service, count in analysis["top_services"][:8]:
        if service:
            print(f"  {service.ljust(15)} {count} packets")

    print(f"\n  ── Top conversations ───────────────────────────")
    for convo, count in analysis["top_conversations"][:5]:
        print(f"  {convo.ljust(40)} {count} packets")

    print("=" * 65)


# ── Export ─────────────────────────────────────────────────────────────────────

def export_to_csv(packets: list, analysis: dict):
    """Saves captured packets and summary to CSV."""
    date_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    # Packet log
    log_path = f"{OUTPUT_DIR}/packets_{date_str}.csv"
    if packets:
        fieldnames = list(packets[0].keys())
        with open(log_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(packets)
        print(f"\n  Saved packet log: {log_path}")

    # Summary
    summary_path = f"{OUTPUT_DIR}/summary_{date_str}.csv"
    with open(summary_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Metric", "Value"])
        writer.writerow(["Total packets", analysis.get("total_packets", 0)])
        writer.writerow(["Total bytes", analysis.get("total_bytes", 0)])
        writer.writerow(["Avg packet size", analysis.get("avg_packet_size", 0)])
        writer.writerow([])
        writer.writerow(["Protocol", "Packets", "Bytes"])
        for proto, count in analysis.get("proto_counts", {}).items():
            bytes_ = analysis.get("proto_bytes", {}).get(proto, 0)
            writer.writerow([proto, count, bytes_])
        writer.writerow([])
        writer.writerow(["Top Source IPs", "Packets"])
        for ip, count in analysis.get("top_src_ips", []):
            writer.writerow([ip, count])
    print(f"  Saved summary:    {summary_path}")


# ── Synthetic demo mode ────────────────────────────────────────────────────────

def run_demo():
    """
    Generates synthetic packet data for demonstration
    when scapy is unavailable or no sudo access.
    """
    import random
    import time

    print("Running in demo mode — generating synthetic network traffic...\n")
    print(f"  {'PROTO':<6} {'SRC IP':<18} {'':2} {'DST IP':<18} {'SIZE':>6}  INFO")
    print("  " + "-" * 62)

    protocols  = ["TCP", "UDP", "TCP", "TCP", "DNS", "ICMP", "TCP"]
    src_ips    = ["192.168.1.10", "192.168.1.20", "10.0.0.5",
                  "172.16.0.1", "192.168.1.1"]
    dst_ips    = ["8.8.8.8", "1.1.1.1", "142.250.180.46",
                  "151.101.1.140", "192.168.1.1", "172.217.0.1"]
    services   = ["HTTPS", "DNS", "HTTP", "SSH", "ICMP Echo Request"]

    records = []
    for i in range(50):
        proto   = random.choice(protocols)
        src     = random.choice(src_ips)
        dst     = random.choice(dst_ips)
        size    = random.randint(64, 1500)
        service = random.choice(services)
        sport   = random.randint(1024, 65535)
        dport   = {"HTTPS": 443, "DNS": 53, "HTTP": 80,
                   "SSH": 22}.get(service, random.randint(80, 8080))

        record = {
            "timestamp":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip":     src,
            "dst_ip":     dst,
            "protocol":   proto,
            "src_port":   sport,
            "dst_port":   dport,
            "service":    service,
            "size_bytes": size,
            "flags":      "SYN+ACK" if proto == "TCP" else "",
            "info":       f"{sport} → {dport} [{service}]",
        }
        records.append(record)

        print(f"  {proto.ljust(6)} {src.ljust(18)} → "
              f"{dst.ljust(18)} {str(size).rjust(6)}B  "
              f"{sport} → {dport} [{service}]")
        time.sleep(0.05)

    return records


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Network Packet Analyser — capture and analyse network traffic"
    )
    parser.add_argument("--count",   type=int, default=100,
                        help="Number of packets to capture (default: 100)")
    parser.add_argument("--filter",  type=str, default="",
                        help="BPF filter string e.g. 'tcp', 'udp', 'port 443'")
    parser.add_argument("--iface",   type=str, default=None,
                        help="Network interface to capture on (default: auto)")
    parser.add_argument("--summary", action="store_true",
                        help="Show summary only, no live packet display")
    parser.add_argument("--demo",    action="store_true",
                        help="Run in demo mode with synthetic data")
    args = parser.parse_args()

    print("Network Packet Analyser")
    print("=" * 40)

    if args.demo or not SCAPY_AVAILABLE:
        packets = run_demo()
    else:
        print(f"Capturing {args.count} packets"
              + (f" (filter: {args.filter})" if args.filter else "") + "...\n")
        print(f"  {'PROTO':<6} {'SRC IP':<18} {'':2} {'DST IP':<18} "
              f"{'SIZE':>6}  INFO")
        print("  " + "-" * 62)

        try:
            sniff(
                count=args.count,
                filter=args.filter if args.filter else None,
                iface=args.iface,
                prn=packet_callback if not args.summary else None,
                store=True,
            )
            packets = captured_packets
        except PermissionError:
            print("\n  Permission denied. Run with sudo:")
            print("  sudo python analyser.py")
            print("\n  Running demo mode instead...\n")
            packets = run_demo()

    analysis = analyse_traffic(packets)
    print_summary(analysis)
    export_to_csv(packets, analysis)
    print("\nCapture complete.")


if __name__ == "__main__":
    main()
