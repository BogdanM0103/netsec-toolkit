import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

target = "scanme.nmap.org"

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

ports = range(20, 1024)
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