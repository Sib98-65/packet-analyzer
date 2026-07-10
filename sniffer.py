import sys
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP

def packet_callback(packet):
    """
    Callback function that is executed for each captured packet.
    It extracts key details like IPs, protocol, ports, and size,
    and handles packets without IP layers gracefully.
    """
    try:
        # 1. Get the packet size in bytes.
        # len() on a Scapy packet returns the size of the raw packet.
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
            # Scapy classes for ICMPv6 can vary (e.g., ICMPv6ND_NS, etc.).
            # We can check if the next header protocol number is 58 (ICMPv6).
            elif next_header == 58:
                protocol = "ICMP"
                src_port = "N/A"
                dst_port = "N/A"
            else:
                protocol = f"other ({next_header})"
                src_port = "N/A"
                dst_port = "N/A"
                
        else:
            # 3. Handle packets that don't have IP layers (e.g., ARP, STP, raw Layer 2 ethernet frames)
            src_ip = "N/A"
            dst_ip = "N/A"
            protocol = "other"
            src_port = "N/A"
            dst_port = "N/A"

        # 4. Print the packet details in a readable format.
        print(f"[+] Packet: {src_ip} -> {dst_ip} | Protocol: {protocol} | Ports: {src_port} -> {dst_port} | Size: {packet_size} bytes")

    except Exception as e:
        # Catch any unexpected errors within the callback to prevent the sniffer from crashing.
        print(f"[-] Error processing packet: {e}", file=sys.stderr)

def capture_packets(count=20):
    """
    Starts Scapy's packet sniffer.
    - count: Number of packets to capture before stopping.
    - prn: The callback function called on each packet.
    - store: Set to False so Scapy doesn't keep packets in memory, reducing memory usage.
    """
    print(f"[*] Starting packet capture. Sniffing {count} packets...")
    print("[*] Note: On Windows, packet sniffing may require Administrator privileges or Npcap to be installed.")
    
    try:
        # sniff() is the core Scapy function that listens to network interfaces.
        # prn=packet_callback runs our function for every captured packet.
        # count specifies the limit of packets to capture.
        sniff(prn=packet_callback, count=count, store=False)
        print("[*] Packet capture complete.")
    except PermissionError:
        print("[-] Error: Insufficient permissions. Please run the script as an Administrator.", file=sys.stderr)
    except Exception as e:
        print(f"[-] An error occurred during capture: {e}", file=sys.stderr)

if __name__ == '__main__':
    # When executed directly, start the capture with a default count of 20 packets.
    capture_packets(count=20)
