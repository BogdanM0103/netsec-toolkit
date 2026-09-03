import socket

target = "scanme.nmap.org"
port = 80
def scan_port(target, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"Port {port} is open on {target}.")
            try:
                banner = sock.recv(1024).decode().strip()
                print(f"Banner: {banner}")
            except socket.timeout:
                print("No banner received.")

for port in range(20, 30):
    scan_port(target, port)