#!/usr/bin/env python3
"""
Basic Network Sniffer
======================
Captures live network traffic and displays useful information about each
packet: source/destination IPs, protocol, ports, and a preview of the
payload. Built with Scapy.

IMPORTANT:
- You must run this with root/administrator privileges (raw sockets require it).
  e.g.  sudo python3 network_sniffer.py
- Only capture traffic on networks/interfaces you own or have explicit
  permission to monitor. Sniffing traffic you don't own may be illegal.

Usage:
    sudo python3 network_sniffer.py                 # sniff all traffic, no limit
    sudo python3 network_sniffer.py -i eth0          # choose interface
    sudo python3 network_sniffer.py -c 50            # stop after 50 packets
    sudo python3 network_sniffer.py -f "tcp port 80" # BPF filter (like tcpdump)
    sudo python3 network_sniffer.py --save capture.pcap  # also save to a pcap file
"""

import argparse
import datetime
import textwrap

from scapy.all import sniff, wrpcap, conf
from scapy.packet import Raw
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP

# Well-known ports -> protocol names, just so output is more readable
PORT_NAMES = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-ALT",
}

packet_count = 0
captured_packets = []  # only used if --save is passed


def guess_service(port):
    return PORT_NAMES.get(port, "")


def format_payload(payload_bytes, max_len=80):
    """Return a printable, truncated preview of raw payload bytes."""
    if not payload_bytes:
        return None
    try:
        text = payload_bytes.decode("utf-8", errors="replace")
    except Exception:
        text = repr(payload_bytes)
    text = text.replace("\n", "\\n").replace("\r", "\\r")
    if len(text) > max_len:
        text = text[:max_len] + "..."
    return text


def process_packet(pkt):
    """Callback invoked by scapy for every captured packet."""
    global packet_count
    packet_count += 1

    timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    lines = [f"\n[{packet_count}] {timestamp}"]

    # --- Layer 2 (Ethernet) ---
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        lines.append(f"    Ethernet   : {eth.src} -> {eth.dst}")

    # --- ARP (no IP layer involved) ---
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        op = "request" if arp.op == 1 else "reply" if arp.op == 2 else str(arp.op)
        lines.append(f"    ARP        : {arp.psrc} says {op} for {arp.pdst}")

    # --- Layer 3 (IPv4 / IPv6) ---
    src_ip = dst_ip = None
    proto_name = None
    if pkt.haslayer(IP):
        ip = pkt[IP]
        src_ip, dst_ip = ip.src, ip.dst
        proto_num_to_name = {1: "ICMP", 6: "TCP", 17: "UDP"}
        proto_name = proto_num_to_name.get(ip.proto, str(ip.proto))
        lines.append(f"    IPv4       : {src_ip} -> {dst_ip}  (proto={proto_name}, ttl={ip.ttl}, len={ip.len})")
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        src_ip, dst_ip = ip6.src, ip6.dst
        lines.append(f"    IPv6       : {src_ip} -> {dst_ip}  (nh={ip6.nh}, hlim={ip6.hlim})")

    # --- Layer 4 (TCP / UDP / ICMP) ---
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        flags = tcp.sprintf("%TCP.flags%")
        src_svc = guess_service(tcp.sport)
        dst_svc = guess_service(tcp.dport)
        src_label = f"{tcp.sport}({src_svc})" if src_svc else str(tcp.sport)
        dst_label = f"{tcp.dport}({dst_svc})" if dst_svc else str(tcp.dport)
        lines.append(f"    TCP        : port {src_label} -> {dst_label}  flags={flags} seq={tcp.seq} ack={tcp.ack}")
    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        src_svc = guess_service(udp.sport)
        dst_svc = guess_service(udp.dport)
        src_label = f"{udp.sport}({src_svc})" if src_svc else str(udp.sport)
        dst_label = f"{udp.dport}({dst_svc})" if dst_svc else str(udp.dport)
        lines.append(f"    UDP        : port {src_label} -> {dst_label}  len={udp.len}")
    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        lines.append(f"    ICMP       : type={icmp.type} code={icmp.code}")

    # --- Payload preview ---
    if pkt.haslayer(Raw):
        payload = bytes(pkt[Raw].load)
        preview = format_payload(payload)
        if preview:
            lines.append(f"    Payload    : {preview}")
        lines.append(f"    Payload len: {len(payload)} bytes")

    print("\n".join(lines))

    if args.save:
        captured_packets.append(pkt)


def main():
    print(f"Starting capture on interface: {args.iface or conf.iface}")
    if args.filter:
        print(f"BPF filter: {args.filter}")
    if args.count:
        print(f"Will stop after {args.count} packets")
    print("Press Ctrl+C to stop early.\n")

    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            prn=process_packet,
            count=args.count if args.count else 0,  # 0 = infinite
            store=False,
        )
    except KeyboardInterrupt:
        print("\nStopped by user.")
    except PermissionError:
        print("\nPermission denied. Try running with sudo/administrator privileges.")
        return
    finally:
        print(f"\nTotal packets captured: {packet_count}")
        if args.save and captured_packets:
            wrpcap(args.save, captured_packets)
            print(f"Saved {len(captured_packets)} packets to {args.save}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Basic Network Sniffer built with Scapy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(__doc__),
    )
    parser.add_argument("-i", "--iface", default=None, help="Network interface to sniff on (default: scapy's default)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (default: unlimited)")
    parser.add_argument("-f", "--filter", default=None, help='BPF filter string, e.g. "tcp port 80" or "udp"')
    parser.add_argument("--save", default=None, help="Save captured packets to this .pcap file")
    args = parser.parse_args()
    main()
