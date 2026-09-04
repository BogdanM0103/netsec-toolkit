import socket
import argparse
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

HTTP_PORTS = {80, 8080, 8000, 8888}

def scan_port(target, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            try:
                if port in HTTP_PORTS:
                    request = "GET / HTTP/1.0\r\n\r\n"
                    sock.send(request.encode())          # 1. speak first
                banner = sock.recv(1024).decode(errors="replace").strip()  # 2. receive

                if port in HTTP_PORTS:                    # 3. now extract
                    for line in banner.split("\r\n"):
                        if line.lower().startswith("server:"):
                            banner = line
                            break
            except socket.timeout:
                banner = ""
            return {"port": port, "banner": banner}
        return None
    return None                                        # closed: return None


def parse_ports(spec):
    ports = []
    for part in spec.split(","):        # handle the commas first
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return [p for p in ports if 1 <= p <= 65535]  # filter valid ports

def main():
    # everything that was at the top level goes here, indented one more level
    parser = argparse.ArgumentParser(description="Scan open ports on a target host.")
    parser.add_argument("target", help="Target host to scan (IP or hostname)")
    parser.add_argument("-p", "--ports", type=str, default="1-1024",
                        help="Port range to scan (default: 1-1024)")
    parser.add_argument("--json", metavar="FILE", help="Write results to a JSON file")
    args = parser.parse_args()

    target = args.target
    ports = parse_ports(args.ports)
    open_ports = []

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, target, port) for port in ports]
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)

    open_ports.sort(key=lambda r: r["port"])
    for r in open_ports:
        print(f"Port {r['port']} is open. Banner: {r['banner']}")
    print(f"\n{len(open_ports)} open ports found.")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(open_ports, f, indent=2)
        print(f"Results written to {args.json}")


if __name__ == "__main__":
    main()