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
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit.",
    )
    return parser.parse_args()

# ------ Interface Lister ------
def list_interfaces() -> None:
    """Display available network interfaces with friendly names."""
    from scapy.arch.windows import get_windows_if_list

    interfaces    = get_windows_if_list()

    table = Table(
        title="Available Network Interfaces",
        header_style="bold magenta",
        border_style="cyan",
    )
    table.add_column("Index",       width=8,  style="yellow")
    table.add_column("Name",        width=30, style="cyan")
    table.add_column("Description", style="white")

    # Filter out virtual filter drivers and tunneling adapters
    skip_keywords = ["npcap", "wfp", "qos", "filter", "miniport", "teredo",
                     "6to4", "https", "sstp", "ikev2", "l2tp", "pptp"]

    filtered = [
        iface for iface in interfaces
        if not any(
            kw in iface.get("name", "").lower() or
            kw in iface.get("description", "").lower()
            for kw in skip_keywords
        )
    ]

    for i, iface in enumerate(filtered):
        friendly_name = iface.get("name", "Unknown")
        description   = iface.get("description", "")
        table.add_row(str(i), friendly_name, description)

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
            self.port_counter[dst_port] += 1
            self.unique_ports[src_ip].add(dst_port)
            
            # SYN flag is 0x02 - set when initiating a new connection
            if flags == 0x02:
                self.syn_counter[src_ip] += 1
                
        # ------- UDP Packets ------
        elif packet.haslayer(UDP):
            dst_port = packet[UDP].dport
            self.port_counter[dst_port] += 1
            self.unique_ports[src_ip].add(dst_port)
            
        # ------- ICMP Packets ------
        elif packet.haslayer(ICMP):
            self.icmp_counter[src_ip] += 1
            
        # ------- Run Detection -------
        self._detect_threats(src_ip)
        
    def _detect_threats(self, src_ip: str) -> None:
        """Check a source IP for suspicious patterns and generate alerts"""
        
        # ------ Port Scan Detection ------
        unique_port_count = len(self.unique_ports[src_ip])
        already_flagged   = any(a["ip"] == src_ip and a["type"] == "port_scan" for a in self.alerts)
        
        if unique_port_count >= PORT_SCAN_THRESHOLD and not already_flagged:
            self.alerts.append({
                "type":     "port_scan",
                "severity": HIGH,
                "ip":       src_ip,
                "detail":   f"IP {src_ip} contacted {unique_port_count} unique ports",
            })
            
        # ------ SYN Flood Detection ------
        syn_count       = self.syn_counter[src_ip]
        already_flagged = any(a["ip"] == src_ip and a["type"] == "syn_flood" for a in self.alerts)
        
        if syn_count >= SYN_FLOOD_THRESHOLD and not already_flagged:
            self.alerts.append({
                "type":     "syn_flood",
                "severity": CRITICAL,
                "ip":       src_ip,
                "detail":   f"IP {src_ip} sent {syn_count} SYN packets",
            })
            
        # ------ ICMP Flood Detection ------
        icmp_count      = self.icmp_counter[src_ip]
        already_flagged = any(a["ip"] == src_ip and a["type"] == "icmp_flood" for a in self.alerts)
        
        if icmp_count >= ICMP_FLOOD_THRESHOLD and not already_flagged:
            self.alerts.append({
                "type":     "icmp_flood",
                "severity": HIGH,
                "ip":       src_ip,
                "detail":   f"IP {src_ip} sent {icmp_count} ICMP packets",
            })
            
# ------ Display Stats ------
def display_stats(store: PacketStore) -> Table:
    """Build and return a Rich Table with current statistics"""
    
    elapsed      = datetime.now() - store.start_time
    elapsed_str  = str(elapsed).split(".")[0]
    top_talkers  = store.ip_counter.most_common(5)
    top_ports    = store.port_counter.most_common(5)
    proto_tcp    = store.proto_counter.get(PROTO_TCP, 0)
    proto_udp    = store.proto_counter.get(PROTO_UDP, 0)
    proto_icmp   = store.proto_counter.get(PROTO_ICMP, 0)
    
    table = Table(
        title=f"Network Analyzer - Live Capture ({elapsed_str})",
        header_style="bold magenta",
        border_style="cyan",
        expand=True,
    )
    
    table.add_column("Metric", style="cyan", width=25)
    table.add_column("Value", style="yellow")
    
    table.add_row("Total Packets",    str(store.total))
    table.add_row("TCP Packets",      str(proto_tcp))
    table.add_row("UDP Packets",      str(proto_udp))
    table.add_row("ICMP Packets",     str(proto_icmp))
    table.add_row("Active Alerts",    str(len(store.alerts)))
    table.add_row("",                 "")
    table.add_row("[bold]Top Talkers[/bold]", "")
    
    for ip, count in top_talkers:
        table.add_row(f"  {ip}", str(count))
        
    table.add_row("",                 "")
    table.add_row("[bold]Top Ports[/bold]", "")
    
    for port, count in top_ports:
        table.add_row(f"  Port {port}", str(count))
        
    return table

# ------ Start Capture ------
def start_capture(interface: str, count: int, filter_str: str, timeout: int) -> PacketStore:
    """Start capturing packets and return the populated PacketStore."""

    store      = PacketStore()
    stop_event = Event()

    console.print(f"[cyan]Starting capture on [bold]{interface}[/bold]...[/cyan]")
    console.print("[dim]Press Ctrl+C to stop.[/dim]\n")

    try:
        with Live(display_stats(store), refresh_per_second=2) as live:

            def packet_callback(packet) -> None:
                """Process each captured packet and refresh the display."""
                store.process_packet(packet)
                live.update(display_stats(store))

            sniff(
                iface=interface,
                prn=packet_callback,
                count=count,
                filter=filter_str,
                timeout=timeout if timeout > 0 else None,
                store=False,
            )

    except KeyboardInterrupt:
        console.print("\n[yellow]Capture stopped by user.[/yellow]")

    return store

# ------ Display Alerts ------
def display_alerts(store: PacketStore) -> None:
    """Display any security alerts generated during capture."""

    if not store.alerts:
        console.print("\n[green]No threats detected during capture.[/green]")
        return

    alert_count = len(store.alerts)

    console.print(f"\n[bold red]Security Alerts Detected: {alert_count}[/bold red]\n")

    table = Table(
        title="Security Alerts",
        header_style="bold magenta",
        border_style="red",
        expand=True,
    )

    table.add_column("Severity", width=12)
    table.add_column("Type",     width=15)
    table.add_column("Detail",   style="white")

    for alert in store.alerts:
        severity    = alert["severity"]
        color       = SEVERITY_COLORS[severity]
        alert_type  = alert["type"].replace("_", " ").title()

        table.add_row(
            f"[{color}]{severity}[/{color}]",
            f"[{color}]{alert_type}[/{color}]",
            alert["detail"],
        )

    console.print(table)


# ------ Main ------
def main() -> None:
    """Main entry point for the network analyzer."""

    console.print("[bold cyan]blankenshipSec Network Analyzer[/bold cyan]")
    console.print("[dim]For authorized use only.[/dim]\n")

    args = parse_arguments()

    if args.list_interfaces:
        list_interfaces()
        return

    if not args.interface:
        console.print("[yellow]No interface specified. Available interfaces:[/yellow]\n")
        list_interfaces()
        console.print("\n[yellow]Use -i to specify an interface.[/yellow]")
        console.print("[dim]Example: python analyzer.py -i 'Ethernet'[/dim]")
        return

    store = start_capture(
        interface  = args.interface,
        count      = args.count,
        filter_str = args.filter,
        timeout    = args.timeout,
    )

    display_alerts(store)

    console.print(f"\n[dim]Total packets captured: {store.total}[/dim]")


if __name__ == "__main__":
    main()