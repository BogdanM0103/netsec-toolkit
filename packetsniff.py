import argparse
from scapy.all import sniff, IP, IPv6, TCP, UDP, DNS, DNSQR, ICMP, ICMPv6EchoRequest, ICMPv6EchoReply

WELL_KNOWN_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 25: "SMTP",
    53: "DNS", 80: "HTTP", 443: "HTTPS", 3389: "RDP",
}

def label(sport, dport):
    if sport in WELL_KNOWN_PORTS:
        return WELL_KNOWN_PORTS[sport]
    elif dport in WELL_KNOWN_PORTS:
        return WELL_KNOWN_PORTS[dport]
    else:
        return "Unknown"


def process_packet(packet):

    sport = None
    dport = None

    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
    elif packet.haslayer(IPv6):
        src = packet[IPv6].src
        dst = packet[IPv6].dst
    else:
        return

    if packet.haslayer('TCP'):
        protocol = 'TCP'
        sport = packet['TCP'].sport
        dport = packet['TCP'].dport
    elif packet.haslayer('UDP'):
        protocol = 'UDP'
        sport = packet['UDP'].sport
        dport = packet['UDP'].dport
    else:
        protocol = 'Other'

    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        domain = packet[DNSQR].qname.decode().rstrip(".") if packet.haslayer(DNSQR) else "Unknown"
        print(f"[DNS Query] {src} -> {dst}  Domain: {domain}")
        return                                    # <-- stops the double print
    elif packet.haslayer(DNS) and packet[DNS].qr == 1:
        domain = packet[DNSQR].qname.decode().rstrip(".") if packet.haslayer(DNSQR) else "Unknown"
        print(f"[DNS Response] {src} -> {dst}  Domain: {domain}")
        return                                    # <-- same here


    if sport is not None:
        service = label(sport, dport)

        if sport == 80 or dport == 80:
            print(f"Insecure HTTP traffic detected: {src}:{sport} -> {dst}:{dport}")
            if packet.haslayer('Raw'):
                payload = packet['Raw'].load
                print(f"    Readable data: {payload[:80]}")   # first 80 bytes
            return
        print(f"[{service}] [{protocol}] {src}:{sport} -> {dst}:{dport}")

def main():
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument("-c", type=int, default=10, help="Number of packets to capture (default: 10)")
    parser.add_argument("-f", type=str, default="", help="Filter expression (default: capture all packets)")
    args = parser.parse_args()
    print(f"Capturing {args.c} packets with filter: '{args.f}'")
    sniff(count=args.c, filter=args.f, prn=process_packet)

if __name__ == "__main__":
    main()