import sys
import argparse
from datetime import datetime
from collections import Counter
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel

# Initialize the Rich Console objects. Console handles styled text printing to the terminal.
console = Console()
console_err = Console(stderr=True)

def show_summary_and_export(captured_data, export_file=None):
    """
    Computes summary statistics and exports captured data to a CSV file.
    - captured_data: List of packet dictionaries.
    - export_file: Filename path for CSV output.
    """
    total_packets = len(captured_data)
    if total_packets == 0:
        console.print("\n[bold yellow][*] No packets were captured. Skipping summary and export.[/bold yellow]")
        return

    # 1. Calculate summary metrics
    # Sum the packet size in bytes for all packets
    total_bytes = sum(pkt["size"] for pkt in captured_data)
    # Convert total bytes to Kilobytes (1 KB = 1024 bytes)
    total_kb = total_bytes / 1024.0

    # Count occurrences of each protocol
    protocols = [pkt["protocol"] for pkt in captured_data]
    proto_counts = Counter(protocols)

    # Count occurrences of source IPs to find the top "talkers"
    # We ignore packets that do not have IP layers ("N/A")
    src_ips = [pkt["source_ip"] for pkt in captured_data if pkt["source_ip"] != "N/A"]
    top_talkers = Counter(src_ips).most_common(5)

    # 2. Building the Rich panel content string
    summary_text = []
    summary_text.append(f"Total Packets Captured: [cyan]{total_packets}[/cyan]")
    summary_text.append(f"Total Data Captured: [cyan]{total_kb:.2f} KB[/cyan] ({total_bytes} bytes)\n")

    summary_text.append("[bold magenta]Protocol Breakdown:[/bold magenta]")
    for proto, count in proto_counts.items():
        percentage = (count / total_packets) * 100
        summary_text.append(f"  • {proto}: [cyan]{count}[/cyan] ({percentage:.1f}%)")

    summary_text.append("\n[bold magenta]Top 5 Talkers (Source IPs):[/bold magenta]")
    if top_talkers:
        for idx, (ip, count) in enumerate(top_talkers, 1):
            summary_text.append(f"  {idx}. {ip} : [cyan]{count}[/cyan] packets")
    else:
        summary_text.append("  No IP packets captured.")

    # Panel with the summary
    summary_panel = Panel(
        "\n".join(summary_text),
        title="[bold green]Capture Statistics[/bold green]",
        expand=False,
        border_style="green"
    )
    console.print(summary_panel)

    # 3. Export to CSV (built-in csv module)
    if export_file:
        try:
            import pandas as pd
            # Create a DataFrame from our list of dictionaries
            df = pd.DataFrame(captured_data)
            # Write to CSV file without writing the DataFrame row index
            df.to_csv(export_file, index=False)
            console.print(f"\n[bold green][+] Successfully exported capture data using pandas to [cyan]{export_file}[/cyan][/bold green]")
        except Exception as pandas_err:
            console.print(f"\n[yellow][!] Pandas export failed (e.g. dependency conflict): {pandas_err}[/yellow]")
            console.print("[yellow][*] Attempting fallback export using Python's built-in csv module...[/yellow]")
            try:
                import csv
                keys = captured_data[0].keys()
                with open(export_file, 'w', newline='', encoding='utf-8') as f:
                    dict_writer = csv.DictWriter(f, fieldnames=keys)
                    dict_writer.writeheader()
                    dict_writer.writerows(captured_data)
                console.print(f"[bold green][+] Successfully exported capture data to [cyan]{export_file}[/cyan][/bold green]")
            except Exception as csv_err:
                console_err.print(f"[bold red][-] Failed to export CSV: {csv_err}[/bold red]")


def capture_packets(count=20, protocol_filter=None, interface=None, export_file=None):
    """
    Starts Scapy's packet sniffer and displays results in a live-updating table.
    - count: Number of packets to capture.
    - protocol_filter: BPF filter string to filter packets at kernel level.
    - interface: Specific network interface to sniff on.
    - export_file: Filename to export capture data to.
    """
    # Map BPF filter or protocol name back to a readable format for the table title
    protocol_name = "all"
    if protocol_filter:
        if "icmp" in protocol_filter:
            protocol_name = "icmp"
        else:
            protocol_name = protocol_filter
            
    iface_title_desc = interface if interface else "auto"
    table_title = f"Packet Analyzer — Protocol: {protocol_name} | Count: {count} | Interface: {iface_title_desc}"
    
    filter_desc = protocol_filter if protocol_filter else "all protocols"
    iface_desc = interface if interface else "auto-select"
    
    console.print("[bold yellow][*] Starting packet capture...[/bold yellow]")
    console.print(f"[*] Interface: [cyan]{iface_desc}[/cyan] | Filter: [cyan]{filter_desc}[/cyan] | Count: [cyan]{count}[/cyan]")
    console.print("[*] Note: On Windows, packet sniffing may require Administrator privileges or Npcap to be installed.\n")

    # Creating the Rich Table
    table = Table(title=table_title, show_header=True, header_style="bold magenta")
    table.add_column("No.", justify="right", style="cyan")
    table.add_column("Source IP", width=30)
    table.add_column("Destination IP", width=30)
    table.add_column("Protocol", justify="center")
    table.add_column("Source Port", justify="right")
    table.add_column("Destination Port", justify="right")
    table.add_column("Size (bytes)", justify="right", style="green")

    # List of dicts to store capture details for CSV/Summary
    captured_packets_data = []
    packet_count = 0

    # Callback executed on each packet arrival
    def packet_callback(packet):
        nonlocal packet_count
        try:
            packet_count += 1
            packet_size = len(packet)
            
            # Extract high-precision timestamp
            try:
                pkt_time = float(packet.time)
            except AttributeError:
                pkt_time = datetime.now().timestamp()
            
            timestamp = datetime.fromtimestamp(pkt_time).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

            # Extract layer information and prepare styled and unstyled strings
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto_num = packet[IP].proto
                
                if packet.haslayer(TCP):
                    protocol_styled = "[blue]TCP[/blue]"
                    protocol_plain = "TCP"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif packet.haslayer(UDP):
                    protocol_styled = "[green]UDP[/green]"
                    protocol_plain = "UDP"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                elif packet.haslayer(ICMP):
                    protocol_styled = "[yellow]ICMP[/yellow]"
                    protocol_plain = "ICMP"
                    src_port = "N/A"
                    dst_port = "N/A"
                else:
                    protocol_styled = f"[white]other ({proto_num})[/white]"
                    protocol_plain = f"other ({proto_num})"
                    src_port = "N/A"
                    dst_port = "N/A"
                    
            elif packet.haslayer(IPv6):
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
                next_header = packet[IPv6].nh
                
                if packet.haslayer(TCP):
                    protocol_styled = "[blue]TCP[/blue]"
                    protocol_plain = "TCP"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif packet.haslayer(UDP):
                    protocol_styled = "[green]UDP[/green]"
                    protocol_plain = "UDP"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                elif next_header == 58:
                    protocol_styled = "[yellow]ICMP[/yellow]"
                    protocol_plain = "ICMP"
                    src_port = "N/A"
                    dst_port = "N/A"
                else:
                    protocol_styled = f"[white]other ({next_header})[/white]"
                    protocol_plain = f"other ({next_header})"
                    src_port = "N/A"
                    dst_port = "N/A"
                    
            else:
                src_ip = "N/A"
                dst_ip = "N/A"
                protocol_styled = "[white]other[/white]"
                protocol_plain = "other"
                src_port = "N/A"
                dst_port = "N/A"

            # Add to list of captured packets for summary and export
            captured_packets_data.append({
                "timestamp": timestamp,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "protocol": protocol_plain,
                "source_port": src_port,
                "destination_port": dst_port,
                "size": packet_size
            })

            # Render to live table
            table.add_row(
                str(packet_count),
                src_ip,
                dst_ip,
                protocol_styled,
                str(src_port),
                str(dst_port),
                str(packet_size)
            )

        except Exception as e:
            # We catch exceptions to prevent the callback from crashing the sniff stream.
            pass

    try:
        # Using rich.live.Live as a context manager for terminal UI refresh
        with Live(table, console=console, refresh_per_second=4):
            sniff(prn=packet_callback, count=count, store=False, filter=protocol_filter, iface=interface)
        
        console.print("\n[bold green][*] Packet capture complete.[/bold green]")
        
    except KeyboardInterrupt:
        console.print("\n[bold yellow][*] Capture interrupted by user (Ctrl+C).[/bold yellow]")
    except PermissionError:
        console_err.print("\n[bold red][-] Error: Insufficient permissions. Please run as Administrator.[/bold red]")
    except Exception as e:
        console_err.print(f"\n[bold red][-] An error occurred: {e}[/bold red]")
    finally:
        # Show statistics summary and export data (runs on success, interrupt, or crash)
        show_summary_and_export(captured_packets_data, export_file)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="A beginner-friendly live network packet sniffer using Scapy and Rich."
    )
    parser.add_argument(
        "--protocol",
        choices=["tcp", "udp", "icmp", "all"],
        default="all",
        help="Filter to only show packets of a specific protocol (choices: tcp, udp, icmp, all; default: all)"
    )
    parser.add_argument(
        "--count",
        type=int,
        default=20,
        help="Number of packets to capture (default: 20)"
    )
    parser.add_argument(
        "--interface",
        default=None,
        help="Specify which network interface to sniff on (default: let Scapy auto-select)"
    )
    parser.add_argument(
        "--export",
        default=None,
        help="Path/filename to export the captured packets to as a CSV file (optional)"
    )
    
    args = parser.parse_args()
    
    bpf_filter = None
    if args.protocol != "all":
        if args.protocol == "icmp":
            bpf_filter = "icmp or icmp6"
        else:
            bpf_filter = args.protocol
            
    capture_packets(
        count=args.count,
        protocol_filter=bpf_filter,
        interface=args.interface,
        export_file=args.export
    )
