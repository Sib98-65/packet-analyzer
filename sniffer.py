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

def show_summary_and_export(captured_data, export_file=None, detect_anomalies=False):
    """
    Computes summary statistics, performs ML anomaly detection, and exports captured data to a CSV file.
    - captured_data: List of packet dictionaries.
    - export_file: Filename path for CSV output.
    - detect_anomalies: Boolean to enable scikit-learn Isolation Forest anomaly detection.
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

    # 2. Build the Rich panel content string
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

    # 3. Perform Anomaly Detection if enabled
    if detect_anomalies:
        summary_text.append("\n[bold magenta]Anomaly Detection (Isolation Forest):[/bold magenta]")
        
        # Group packets by unique source IP (excluding non-IP packets marked "N/A")
        ip_groups = {}
        for pkt in captured_data:
            ip = pkt["source_ip"]
            if ip == "N/A":
                continue
            if ip not in ip_groups:
                ip_groups[ip] = []
            ip_groups[ip].append(pkt)

        # We need at least 5 unique source IPs to establish a meaningful statistical baseline.
        # Isolation Forest depends on comparing data distributions; too few samples leads to garbage outputs.
        if len(ip_groups) < 5:
            summary_text.append(f"  [yellow][*] Skipped: More data needed ({len(ip_groups)}/5 unique source IPs captured).[/yellow]")
        else:
            try:
                from sklearn.ensemble import IsolationForest
                import numpy as np
                
                ip_list = []
                features_list = []
                
                # Engineer 4 features per source IP:
                # 1. total packet count
                # 2. unique destination ports contacted
                # 3. average packet size
                # 4. packets per second (using time spread)
                for ip, pkts in ip_groups.items():
                    pkt_count = len(pkts)
                    unique_ports = len(set(p["destination_port"] for p in pkts if p["destination_port"] != "N/A"))
                    avg_size = sum(p["size"] for p in pkts) / pkt_count
                    epoch_times = [p["epoch_time"] for p in pkts]
                    time_spread = max(epoch_times) - min(epoch_times)
                    pps = pkt_count / time_spread if time_spread > 0 else float(pkt_count)
                    
                    ip_list.append(ip)
                    features_list.append([pkt_count, unique_ports, avg_size, pps])
                
                X = np.array(features_list)
                
                # Isolation Forest isolates anomalies by randomly partitioning features.
                # Outliers require fewer partitions/splits to isolate, placing them closer to the root of the trees.
                # Contamination=0.1 specifies that we expect approximately 10% of unique source IPs to be anomalies.
                # This is a standard assumption in security monitoring, expecting anomalous behavior to be a small minority.
                model = IsolationForest(contamination=0.1, random_state=42)
                predictions = model.fit_predict(X)
                
                # Compute baseline values of normal traffic (inliers = prediction of 1)
                inliers = [features_list[i] for i, pred in enumerate(predictions) if pred == 1]
                # If no inliers are found (very rare), fall back to the entire dataset
                if not inliers:
                    inliers = features_list
                    
                X_inliers = np.array(inliers)
                mean_pkt_count = np.mean(X_inliers[:, 0])
                mean_unique_ports = np.mean(X_inliers[:, 1])
                mean_avg_size = np.mean(X_inliers[:, 2])
                mean_pps = np.mean(X_inliers[:, 3])
                
                anomalies_found = False
                for idx, pred in enumerate(predictions):
                    # -1 indicates an anomaly/outlier flagged by Isolation Forest
                    if pred == -1:
                        ip = ip_list[idx]
                        features = features_list[idx]
                        pkt_count, unique_ports, avg_size, pps = features
                        
                        reasons = []
                        # Compare the flagged IP's metrics with the normal baseline (mean of inliers)
                        if pkt_count > mean_pkt_count * 2.0:
                            reasons.append("unusually high packet count (possible Denial of Service or heavy transmission)")
                        if unique_ports > mean_unique_ports * 2.0 and unique_ports > 2:
                            reasons.append("unusually high unique destination ports contacted (possible port scan)")
                        if avg_size > mean_avg_size * 2.0:
                            reasons.append("unusually large average packet size (possible data exfiltration or large transfer)")
                        if avg_size < mean_avg_size * 0.2:
                            reasons.append("unusually small average packet size (possible ping scan or light polling)")
                        if pps > mean_pps * 2.0:
                            reasons.append("unusually high packet rate (possible flooding or automated scanning)")
                            
                        # If none of the simple rules trigger, it's flagged by a combination of factors
                        if not reasons:
                            reasons.append("unusual multi-feature combination of traffic patterns")
                            
                        explanation = ", ".join(reasons)
                        summary_text.append(f"  [red]• IP: {ip}[/red] — {explanation}")
                        anomalies_found = True
                        
                if not anomalies_found:
                    summary_text.append("  [green]No anomalous source IPs detected (all traffic patterns within normal bounds).[/green]")
                    
            except ImportError:
                summary_text.append("  [yellow][!] Error: scikit-learn or numpy is required to run anomaly detection.[/yellow]")
            except Exception as e:
                summary_text.append(f"  [red][-] Error running anomaly detection: {e}[/red]")

    # Render a beautiful panel with the summary
    summary_panel = Panel(
        "\n".join(summary_text),
        title="[bold green]Capture Statistics[/bold green]",
        expand=False,
        border_style="green"
    )
    console.print(summary_panel)

    # 4. Export to CSV. We try using pandas first (as requested),
    # but fall back to the built-in csv module if there's a dependency / compatibility issue.
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
                # Exclude the temporary internal field 'epoch_time' from the CSV output
                keys = [k for k in captured_data[0].keys() if k != "epoch_time"]
                with open(export_file, 'w', newline='', encoding='utf-8') as f:
                    dict_writer = csv.DictWriter(f, fieldnames=keys, extrasaction='ignore')
                    dict_writer.writeheader()
                    dict_writer.writerows(captured_data)
                console.print(f"[bold green][+] Successfully exported capture data to [cyan]{export_file}[/cyan][/bold green]")
            except Exception as csv_err:
                console_err.print(f"[bold red][-] Failed to export CSV: {csv_err}[/bold red]")


def capture_packets(count=20, protocol_filter=None, interface=None, export_file=None, detect_anomalies=False):
    """
    Starts Scapy's packet sniffer and displays results in a live-updating table.
    - count: Number of packets to capture.
    - protocol_filter: BPF filter string to filter packets at kernel level.
    - interface: Specific network interface to sniff on.
    - export_file: Filename to export capture data to.
    - detect_anomalies: Enable anomaly detection on traffic.
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

    # Create the Rich Table
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
                "epoch_time": pkt_time,
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
        # Use rich.live.Live as a context manager for terminal UI refresh
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
        show_summary_and_export(captured_packets_data, export_file, detect_anomalies)

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
    parser.add_argument(
        "--detect-anomalies",
        action="store_true",
        help="Enable machine learning-based anomaly detection on captured traffic (requires scikit-learn)"
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
        export_file=args.export,
        detect_anomalies=args.detect_anomalies
    )
