from scapy.all import sniff, IP, IPv6

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

    if sport is not None:
        service = label(sport, dport)
        if service:
            print(f"[{service}] {protocol}: {src}:{sport} -> {dst}:{dport}")
        else:
            print(f"{protocol}: {src}:{sport} -> {dst}:{dport}")
    else:
        print(f"{protocol}: {src} -> {dst}")

print("Capturing 10 packets...")
sniff(count=10, prn=process_packet)