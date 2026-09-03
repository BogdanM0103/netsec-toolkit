import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

parser = argparse.ArgumentParser(description="Scan open ports on a target host.")
parser.add_argument("target", help="Target host to scan (IP or hostname)")
parser.add_argument("-p", "--ports", type=str, default="1-1024", help="Port range to scan (default: 1-1024)")
args = parser.parse_args()

target = args.target

def scan_port(target, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            try:
                banner = sock.recv(1024).decode(errors="replace").strip()
            except socket.timeout:
                banner = ""
            return {"port": port, "banner": banner}   # open: return info
    return None                                        # closed: return None


def parse_ports(spec):
    ports = []
    for part in spec.split(","):        # handle the commas first
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return ports

ports = parse_ports(args.ports)
open_ports = []

with ThreadPoolExecutor(max_workers=100) as executor:
    # 1. submit a scan_port task for every port, keep the futures
    futures = [executor.submit(scan_port, target, port) for port in ports]

    # 2. as each finishes, get its result; if not None, keep it
    for future in as_completed(futures):
        result = future.result()
        if result is not None:
            open_ports.append(result)

# 3. print results in order
open_ports.sort(key=lambda r: r["port"])
for r in open_ports:
    print(f"Port {r['port']} is open. Banner: {r['banner']}")

print(f"\n{len(open_ports)} open ports found.")