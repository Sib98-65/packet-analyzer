import sys
import argparse
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP

def packet_callback(packet):
    """
    Callback function executed automatically for each captured packet.
    It extracts key details (IPs, protocol, ports, size) and prints
    them in a readable format, handling non-IP packets gracefully.
    """
    try:
        # 1. Get the packet size in bytes.
        packet_size = len(packet)

        # 2. Extract IP layer information if present.
        # We check for IPv4 (IP) or IPv6 layers.
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto_num = packet[IP].proto
            
            # Determine transport layer protocol and ports
            if packet.haslayer(TCP):
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
                src_port = "N/A"
                dst_port = "N/A"
            else:
                # If there's an IP layer but it's another protocol (e.g., IGMP, OSPF)
                protocol = f"other ({proto_num})"
                src_port = "N/A"
                dst_port = "N/A"
                
        elif packet.haslayer(IPv6):
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            next_header = packet[IPv6].nh
            
            # Check transport protocol under IPv6
            if packet.haslayer(TCP):
                protocol = "TCP"
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                protocol = "UDP"
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            # ICMPv6 has protocol number 58
            elif next_header == 58:
                protocol = "ICMP"
                src_port = "N/A"
                dst_port = "N/A"
            else:
                protocol = f"other ({next_header})"
                src_port = "N/A"
                dst_port = "N/A"
                
        else:
            # 3. Handle packets that don't have IP layers (e.g., ARP, raw Ethernet frames)
            src_ip = "N/A"
            dst_ip = "N/A"
            protocol = "other"
            src_port = "N/A"
            dst_port = "N/A"

        # 4. Print the packet details in a clean, readable format.
        print(f"[+] Packet: {src_ip} -> {dst_ip} | Protocol: {protocol} | Ports: {src_port} -> {dst_port} | Size: {packet_size} bytes")

    except Exception as e:
        # Catch unexpected errors within the callback to prevent the sniffer from crashing.
        print(f"[-] Error processing packet: {e}", file=sys.stderr)

def capture_packets(count=20, protocol_filter=None, interface=None):
    """
    Starts Scapy's packet sniffer.
    - count: Number of packets to capture.
    - protocol_filter: BPF filter string (e.g., 'tcp', 'udp', 'icmp') to filter packets at kernel level.
    - interface: Specific network interface to sniff on. None lets Scapy auto-select.
    """
    # Print status message indicating what we are filtering and capturing
    filter_desc = protocol_filter if protocol_filter else "all protocols"
    iface_desc = interface if interface else "auto-select"
    print(f"[*] Starting packet capture...")
    print(f"[*] Interface: {iface_desc} | Filter: {filter_desc} | Count: {count}")
    print("[*] Note: On Windows, packet sniffing may require Administrator privileges or Npcap to be installed.")
    
    try:
        # sniff() is the core Scapy function that listens to network interfaces.
        # - prn: packet callback function.
        # - count: stop after this many packets.
        # - store=False: do not store packets in RAM.
        # - filter: BPF filter string (efficient kernel-level filtering).
        # - iface: specify interface.
        sniff(prn=packet_callback, count=count, store=False, filter=protocol_filter, iface=interface)
        print("[*] Packet capture complete.")
    except PermissionError:
        print("[-] Error: Insufficient permissions. Please run the script as an Administrator.", file=sys.stderr)
    except Exception as e:
        print(f"[-] An error occurred during capture: {e}", file=sys.stderr)

if __name__ == '__main__':
    # 1. Initialize argparse to parse command-line arguments.
    parser = argparse.ArgumentParser(
        description="A beginner-friendly live network packet sniffer using Scapy."
    )
    
    # 2. Add optional command-line arguments with descriptions.
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
    
    # 3. Parse the arguments passed to the script.
    args = parser.parse_args()
    
    # 4. Map the user's protocol choice to a Scapy BPF (Berkeley Packet Filter) filter string.
    # If the user selects 'icmp', we filter for both 'icmp' (IPv4) or 'icmp6' (IPv6).
    bpf_filter = None
    if args.protocol != "all":
        if args.protocol == "icmp":
            bpf_filter = "icmp or icmp6"
        else:
            bpf_filter = args.protocol
            
    # 5. Call capture_packets with the parsed arguments.
    capture_packets(count=args.count, protocol_filter=bpf_filter, interface=args.interface)
