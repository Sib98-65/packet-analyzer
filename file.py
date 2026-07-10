from scapy.all import sniff

def show(pkt):
    print(pkt.summary())

sniff(count=1, prn=show)
