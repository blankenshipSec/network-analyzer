#!/usr/bin/env python3
"""
network-analyzer - A CLI-based network traffic analyzer for capturing and analyzing packets
Author: Joshua Blankenship (blankenshipSec)
GitHub: https://github.com/blankenshipSec/network-analyzer
License: MIT
"""

import argparse
import sys
import time
from collections import defaultdict, Counter
from datetime import datetime
from threading import Event

from scapy.all import (
    sniff,
    IP,
    TCP,
    UDP,
    ICMP,
    DNS,
    ARP,
    Ether,
    get_if_list,
)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live

# ------ Constants ------
console = Console()

# ------ Severity Levels ------
CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
INFO = "INFO"

SEVERITY_COLORS = {
    CRITICAL: "bold red",
    HIGH: "red",
    MEDIUM: "yellow",
    LOW: "cyan",
    INFO: "white",
}

# ------ Protocol Numbers ------
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP = 1

# ------ Detection Thresholds ------
PORT_SCAN_THRESHOLD = 15
SYN_FLOOD_THRESHOLD = 100
ICMP_FLOOD_THRESHOLD = 50

# ------ Argument Parser ------
def parse_arguments():
    """Parse and return CLI arguments."""
    parser = argparse.ArgumentParser(
        prog="analyzer",
        description="A CLI-based network traffic analyzer for capturing and analyzing traffic",
        epilog="Example: python analyzer.py -i eth0 -c 100",
    )
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to capture on (e.g. eth0, Wi-Fi)"
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Number of packets to capture (default: 0 = unlimited)",
    )
    parser.add_argument(
        "-f", "--filter",
        default="",
        help="BPF filter string (e.g. 'tcp', 'udp', 'icmp', 'port 80')",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=0,
        help="Stop capturing after this many seconds (default: 0 = no timeout)",
    )
    return parser.parse_args()

# ------ Interface Lister ------
def list_interfaces() -> None:
    """Display available network interfaces"""
    interfaces = get_if_list()

    table = Table(
        title="Available Network Interfaces",
        header_style="bold magenta",
        border_style="cyan",
    )
    table.add_column("Index", width=8, style="yellow")
    table.add_column("Interface", style="cyan")

    for i, iface in enumerate(interfaces):
        table.add_row(str(i), iface)

    console.print(table)

# ------ Packet Store ------
class PacketStore:
    """Stores captured packets and tracks statistics for analysis"""

    def __init__(self):
        self.packets        = []
        self.ip_counter     = Counter()
        self.proto_counter  = Counter()
        self.port_counter   = Counter()
        self.syn_counter    = Counter()
        self.icmp_counter   = Counter()
        self.unique_ports   = defaultdict(set)
        self.alerts         = []
        self.total          = 0
        self.start_time     = datetime.now()

    def process_packet(self, packet) -> None:
        """Process a single captured packet and update statistics"""
        self.total += 1

        # ------ Extract IP Layer ------
        if not packet.haslayer(IP):
            return
        
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto  = packet[IP].proto

        self.ip_counter[src_ip] += 1
        self.proto_counter[proto] += 1

        # ------- TCP Packets ------
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            flags    = packet[TCP].flags