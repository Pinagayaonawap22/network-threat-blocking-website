import socket

def test_port_usability(host, port, timeout=3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))

        # Basic test for HTTP/HTTPS
        if port in [80, 443]:
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            response = s.recv(1024).decode(errors="ignore")
            if "HTTP" in response:
                return "Usable (Web Service Responding)"

        # SSH check
        elif port == 22:
            response = s.recv(1024).decode(errors="ignore")
            if "SSH" in response:
                return "Usable (SSH Service Responding)"

        # General case
        return "Usable (Connection Accepted)"
    except socket.timeout:
        return "Not usable (Timeout)"
    except Exception as e:
        return f"Not usable ({str(e)})"
    finally:
        s.close()
