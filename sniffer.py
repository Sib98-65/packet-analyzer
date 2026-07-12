import sys
import argparse
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP
from rich.console import Console
from rich.table import Table
from rich.live import Live

# Initialize the Rich Console. Console handles styled text printing to the terminal.
console = Console()

def capture_packets(count=20, protocol_filter=None, interface=None):
    """
    Starts Scapy's packet sniffer and displays results in a live-updating table.
    - count: Number of packets to capture.
    - protocol_filter: BPF filter string to filter packets at kernel level.
    - interface: Specific network interface to sniff on (None = auto-select).
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

    # 1. Create a Rich Table.
    # The Table object defines the structure of our output columns, with a custom dynamic title.
    table = Table(title=table_title, show_header=True, header_style="bold magenta")
    table.add_column("No.", justify="right", style="cyan")
    table.add_column("Source IP", width=30)
    table.add_column("Destination IP", width=30)
    table.add_column("Protocol", justify="center")
    table.add_column("Source Port", justify="right")
    table.add_column("Destination Port", justify="right")
    table.add_column("Size (bytes)", justify="right", style="green")

    # Variable to keep track of the sequential packet number
    packet_count = 0

    # 2. Define the callback inside capture_packets so it has closure access to 'table' and 'packet_count'.
    def packet_callback(packet):
        nonlocal packet_count
        try:
            # Increment the local counter for each received packet
            packet_count += 1
            packet_size = len(packet)

            # Extract IP layer information
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto_num = packet[IP].proto
                
                # Determine transport layer protocol and style with colors:
                # - TCP: Blue
                # - UDP: Green
                # - ICMP: Yellow
                # - Other: White
                if packet.haslayer(TCP):
                    protocol = "[blue]TCP[/blue]"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif packet.haslayer(UDP):
                    protocol = "[green]UDP[/green]"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                elif packet.haslayer(ICMP):
                    protocol = "[yellow]ICMP[/yellow]"
                    src_port = "N/A"
                    dst_port = "N/A"
                else:
                    protocol = f"[white]other ({proto_num})[/white]"
                    src_port = "N/A"
                    dst_port = "N/A"
                    
            elif packet.haslayer(IPv6):
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst
                next_header = packet[IPv6].nh
                
                if packet.haslayer(TCP):
                    protocol = "[blue]TCP[/blue]"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif packet.haslayer(UDP):
                    protocol = "[green]UDP[/green]"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                elif next_header == 58:
                    protocol = "[yellow]ICMP[/yellow]"
                    src_port = "N/A"
                    dst_port = "N/A"
                else:
                    protocol = f"[white]other ({next_header})[/white]"
                    src_port = "N/A"
                    dst_port = "N/A"
                    
            else:
                # Handle non-IP packets gracefully
                src_ip = "N/A"
                dst_ip = "N/A"
                protocol = "[white]other[/white]"
                src_port = "N/A"
                dst_port = "N/A"

            # Add the new row to the table.
            # In a Live display context, adding a row automatically schedules it for rendering.
            table.add_row(
                str(packet_count),
                src_ip,
                dst_ip,
                protocol,
                str(src_port),
                str(dst_port),
                str(packet_size)
            )

        except Exception as e:
            # We catch exceptions to prevent the callback from crashing the sniff stream.
            pass

    try:
        # 3. Use rich.live.Live as a context manager.
        # This keeps the terminal display updated in-place (no screen flicker).
        # We pass it the 'table' and console to print on.
        with Live(table, console=console, refresh_per_second=4):
            # sniff() blocks and runs until the 'count' limit is reached.
            # Every packet captured triggers packet_callback, updating the table live!
            sniff(prn=packet_callback, count=count, store=False, filter=protocol_filter, iface=interface)
        
        console.print("\n[bold green][*] Packet capture complete.[/bold green]")
        
    except PermissionError:
        console.print("\n[bold red][-] Error: Insufficient permissions. Please run as Administrator.[/bold red]", file=sys.stderr)
    except Exception as e:
        console.print(f"\n[bold red][-] An error occurred: {e}[/bold red]", file=sys.stderr)

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
    
    args = parser.parse_args()
    
    bpf_filter = None
    if args.protocol != "all":
        if args.protocol == "icmp":
            bpf_filter = "icmp or icmp6"
        else:
            bpf_filter = args.protocol
            
    capture_packets(count=args.count, protocol_filter=bpf_filter, interface=args.interface)
