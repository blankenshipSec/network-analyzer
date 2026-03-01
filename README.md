# 🔍 Network Analyzer

> A CLI-based network traffic analyzer for capturing and analyzing packets in real time, with built-in threat detection for port scans, SYN floods, and ICMP floods.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

Built by [blankenshipSec](https://github.com/blankenshipSec) | [Portfolio](https://jblankenship.me)

## ✨ Features

- **Live Packet Capture** — Captures traffic in real time on any network interface
- **Protocol Analysis** — Tracks TCP, UDP, and ICMP packet counts
- **Threat Detection** — Detects port scans, SYN floods, and ICMP floods automatically
- **Top Talkers** — Identifies the most active IP addresses on the network
- **Top Ports** — Shows the most frequently contacted destination ports
- **Interface Discovery** — Lists available network interfaces with friendly names
- **BPF Filtering** — Supports Berkeley Packet Filter syntax for targeted captures
- **Rich Terminal Output** — Live updating dashboard with color coded alerts

## 📋 Requirements

- Python 3.10+
- [scapy](https://scapy.net/)
- [rich](https://github.com/Textualize/rich)
- Administrator/root privileges for packet capture

Install dependencies:
```bash
pip install -r requirements.txt
```

## 🚀 Installation
```bash
git clone git@github.com:blankenshipSec/network-analyzer.git
cd network-analyzer
python -m venv venv
source venv/Scripts/activate  # Windows
pip install -r requirements.txt
```

## 🛠️ Usage

> ⚠️ Must be run as Administrator on Windows or with sudo on Linux.
```bash
python analyzer.py -i <interface> [options]
```

### Arguments

| Argument | Short | Default | Description |
|----------|-------|---------|-------------|
| `--interface` | `-i` | Required | Network interface to capture on |
| `--count` | `-c` | `0` (unlimited) | Number of packets to capture |
| `--filter` | `-f` | None | BPF filter string |
| `--timeout` | None | `0` (none) | Stop after this many seconds |
| `--list-interfaces` | None | False | List available interfaces and exit |

### Examples
```bash
# List available interfaces
python analyzer.py --list-interfaces

# Capture 100 packets on Ethernet
python analyzer.py -i "Ethernet 2" -c 100

# Capture only TCP traffic
python analyzer.py -i "Ethernet 2" -f "tcp"

# Capture only HTTP traffic for 30 seconds
python analyzer.py -i "Ethernet 2" -f "port 80" --timeout 30

# Capture unlimited packets until Ctrl+C
python analyzer.py -i "Ethernet 2"
```

## 📊 Example Output
```
blankenshipSec Network Analyzer
For authorized use only.

Starting capture on Ethernet 2...
Press Ctrl+C to stop.

         Network Analyzer — Live Capture (0:00:03)
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┓
┃ Metric                     ┃ Value         ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━┩
│ Total Packets              │ 50            │
│ TCP Packets                │ 32            │
│ UDP Packets                │ 12            │
│ ICMP Packets               │ 0             │
│ Active Alerts              │ 0             │
│                            │               │
│ Top Talkers                │               │
│   192.168.50.209           │ 20            │
│   142.250.26.95            │ 6             │
│                            │               │
│ Top Ports                  │               │
│   Port 443                 │ 9             │
│   Port 1900                │ 4             │
└────────────────────────────┴───────────────┘

No threats detected during capture.
Total packets captured: 50
```

## 🔍 Threat Detection

| Threat | Severity | Trigger |
|--------|----------|---------|
| Port Scan | HIGH | Single IP contacts 15+ unique ports |
| SYN Flood | CRITICAL | Single IP sends 100+ SYN packets |
| ICMP Flood | HIGH | Single IP sends 50+ ICMP packets |

## ⚠️ Known Limitations & Roadmap

### Current Limitations
- Windows only interface discovery (uses `get_windows_if_list`)
- Requires Administrator privileges
- No PCAP export support yet

### Planned Improvements
- [ ] Add PCAP file export
- [ ] Add DNS anomaly detection
- [ ] Add ARP spoofing detection
- [ ] Add cross-platform interface discovery
- [ ] Add JSON report export

## ⚖️ Legal Disclaimer

This tool is intended for **authorized network monitoring and educational purposes only**.
Always obtain proper authorization before capturing traffic on networks you do not own.
The author assumes no liability for misuse of this tool.

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

*Built with Python & [Scapy](https://scapy.net/) | [blankenshipSec](https://github.com/blankenshipSec)*