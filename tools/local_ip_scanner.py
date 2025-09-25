import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

# ===== Get LAN IP =====
def get_lan_ip():
    """Get the local machine's LAN IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return None

# ===== Fast Ping via TCP Connect (port 80) =====
def is_host_alive(ip):
    """Check if host is alive by attempting TCP connect on port 80."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)  # 50 ms timeout
        result = s.connect_ex((str(ip), 80))
        s.close()
        return result == 0 or result == 111  # open or connection refused means host is up
    except:
        return False

# ===== Concurrent Port Scanner =====
def scan_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)  # very fast timeout
        result = s.connect_ex((ip, port))
        s.close()
        if result == 0:
            return port
    except:
        pass
    return None

def scan_ports(ip, start_port=1, end_port=1000, threads=200):
    open_ports = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in range(start_port, end_port + 1)]
        for future in as_completed(futures):
            port = future.result()
            if port:
                open_ports.append(port)
    return sorted(open_ports)

# ===== Full Deep Scan =====
def deep_scan():
    lan_ip = get_lan_ip()
    if not lan_ip:
        return []

    network = ipaddress.ip_network(lan_ip + "/24", strict=False)
    devices_online = []

    # Step 1: Find online devices
    with ThreadPoolExecutor(max_workers=200) as executor:
        futures = {executor.submit(is_host_alive, host): str(host) for host in network.hosts()}
        for future in as_completed(futures):
            ip = futures[future]
            if future.result():
                ports = scan_ports(ip, 1, 1000, threads=200)
                devices_online.append({
                    "ip": ip,
                    "open_ports": ports
                })

    return devices_online

if __name__ == "__main__":
    deep_scan()
