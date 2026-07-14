# Packet Analyzer

A command-line network packet sniffer and analyzer built with Python and Scapy. Captures live network traffic, displays it in a real-time terminal dashboard, and exports session data with summary statistics.

Built as a portfolio project to demonstrate practical networking, Python, and cybersecurity fundamentals.

\---

## Features

* **Live packet capture** using Scapy, with protocol/IP/port/size extraction
* **CLI filtering** — filter by protocol (TCP/UDP/ICMP), packet count, and network interface
* **Live-updating terminal dashboard** built with `rich` — color-coded protocol table
* **CSV export** of captured session data for later analysis
* **Session summary statistics** — protocol breakdown, top talkers, total data captured
* **Graceful interrupt handling** — Ctrl+C mid-capture still saves data and shows a summary
* **Anomaly detection** using scikit-learn (Isolation Forest) to flag source IPs showing potential port-scan or traffic-burst behavior

\---

## Tech Stack

|Tool|Purpose|
|-|-|
|Python 3.10+|Core language|
|[Scapy](https://scapy.net/)|Packet capture and parsing|
|[Rich](https://github.com/Textualize/rich)|Live terminal table/dashboard|
|[pandas](https://pandas.pydata.org/)|CSV export and stats|
|scikit-learn|Anomaly detection *(planned)*|
|[Npcap](https://npcap.com/)|Windows packet capture driver|

Built using [Antigravity](https://antigravity.google) (Google's agentic IDE) as an AI-assisted development environment.

\---

## Requirements

* Windows 10/11, macOS, or Linux
* Python 3.9+
* Npcap (Windows) or libpcap (macOS/Linux) for raw packet access
* Administrator/root privileges to run (packet capture requires elevated access)

\---

## Installation

```bash
# Clone the repo
git clone https://github.com/<your-username>/packet-analyzer.git
cd packet-analyzer

# Create and activate a virtual environment
python3 -m venv venv
source venv/Scripts/activate    # Git Bash on Windows
# venv\\Scripts\\activate          # Windows CMD
# source venv/bin/activate       # macOS/Linux

# Install dependencies
pip install -r requirements.txt
```

**Windows users:** install [Npcap](https://npcap.com/) first (check "WinPcap API-compatible mode" during setup) — required for Scapy to capture packets.

\---

## Usage

Run as Administrator/root (required for raw packet capture):

```bash
python sniffer.py --help
```

**Basic capture (20 packets, default):**

```bash
python sniffer.py
```

**Filter by protocol:**

```bash
python sniffer.py --protocol tcp --count 50
python sniffer.py --protocol udp
```

**Specify a network interface:**

```bash
python sniffer.py --interface "Wi-Fi" --count 100
```

**Export captured data to CSV:**

```bash
python sniffer.py --count 50 --export capture.csv
```

**Enable anomaly detection (flags source IPs with unusual behavior, e.g. potential port scans):**

```bash
python sniffer.py --count 100 --detect-anomalies
```

Requires at least 5 unique source IPs in the capture for meaningful results; smaller captures will skip detection with a message explaining why.

Press **Ctrl+C** at any time to stop capture early — a summary will still print and the CSV (if requested) will still save whatever was captured.

### Example output

```
Packet Analyzer — Protocol: tcp | Count: 10 | Interface: auto

┏━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━┳════════┓
┃ No. ┃ Source IP     ┃ Destination IP┃ Protocol ┃ Src Port  ┃ Dst Port    ┃  Size  ┃
┡━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━╇════════┩
│  1  │ 192.168.1.5   │ 142.250.190.14│  TCP     │  54213    │  443        │  74    │
└─────┴───────────────┴───────────────┴──────────┴───────────┴─────────────┴────────┘

Summary
Total packets captured: 10
Protocol breakdown: TCP 80% | UDP 20%
Top talkers: 192.168.1.5 (8 packets), 192.168.1.20 (2 packets)
Total data captured: 6.2 KB
```

\---

## Project Structure

```
packet-analyzer/
├── sniffer.py          # Main sniffer script
├── requirements.txt    # Python dependencies
├── .gitignore
└── README.md
```

\---

## Development Notes

This project was built incrementally, using Antigravity's agentic coding assistant with human review at each stage (Default security mode — manual review required for all terminal commands and file changes outside the working folder).

**Build stages:**

1. Environment setup (Python, Scapy, Npcap, virtual environment, Git/GitHub)
2. Core packet capture loop — IP/protocol/port/size extraction with graceful error handling
3. CLI argument parsing (`argparse`) — protocol/count/interface filtering using Scapy's BPF filter
4. Live terminal dashboard using `rich` (`Live` + `Table`) with color-coded protocols
5. CSV export (`pandas`) and session summary statistics, with graceful Ctrl+C handling
6. Anomaly detection using scikit-learn (Isolation Forest) — per-source-IP feature engineering (unique ports contacted, packet rate, average size) to flag possible port scans or traffic bursts

\---

## Legal \& Ethical Note

This tool is intended for capturing traffic **only on networks you own or have explicit permission to monitor** (e.g., your own home network). Capturing traffic on networks you don't control or don't have permission to monitor (public Wi-Fi, college/office networks, etc.) may be illegal. Use responsibly.

\---

