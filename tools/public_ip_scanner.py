import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

def get_public_ip():
    try:
        return requests.get("https://api.ipify.org", timeout=5).text.strip()
    except:
        return None

def scan_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)  # Slightly longer timeout for WAN latency
        result = s.connect_ex((ip, port))
        s.close()
        if result == 0:
            return port
    except:
        pass
    return None

def scan_ports(ip, start_port=1, end_port=6000, threads=200):
    open_ports = []
    print(f"=== Scanning Open Ports on {ip} ===")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in range(start_port, end_port + 1)]
        for future in as_completed(futures):
            port = future.result()
            if port:
                open_ports.append(port)

    if open_ports:
        print("\n[+] Open Ports Found:")
        for port in sorted(open_ports):
            print(f"    - Port {port}")
    else:
        print("\nNo open ports found.")
    print("Scan complete.\n")
    return open_ports

if __name__ == "__main__":
    public_ip = get_public_ip()
    if public_ip:
        print(f"Detected Public IP: {public_ip}\n")
        scan_ports(public_ip, 1, 6000, threads=200)
    else:
        print("Could not detect public IP.")
