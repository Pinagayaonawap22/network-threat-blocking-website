# tools/nmap_scanner.py
import subprocess
import xml.etree.ElementTree as ET
import shlex
import shutil
import platform
from typing import List, Dict, Optional

DEFAULT_NMAP = "nmap"

def find_nmap_executable() -> Optional[str]:
    path = shutil.which(DEFAULT_NMAP) or shutil.which("nmap.exe")
    return path

def run_nmap_xml(target: str, ports: str = "1-1000", extra_args: str = "") -> str:
    nmap_bin = find_nmap_executable()
    if not nmap_bin:
        raise RuntimeError("nmap not found on PATH. Install nmap and add to PATH.")

    is_windows = platform.system().lower().startswith("win")
    # Default scan mode: -sT on Windows, -sS on Unix unless user provided them
    if "-sS" in extra_args or "-sT" in extra_args:
        scan_mode = ""
    else:
        scan_mode = "-sT" if is_windows else "-sS"

    # Use -Pn by default to reduce host discovery time; caller can override by providing -Pn or not
    if "-Pn" in extra_args:
        hostflag = ""
    else:
        hostflag = "-Pn"

    base_args = f"{scan_mode} -T4 {hostflag} {extra_args}".strip()
    cmd = f"{shlex.quote(nmap_bin)} {base_args} -p {ports} -oX - {shlex.quote(target)}"

    try:
        proc = subprocess.run(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=600)
    except Exception as e:
        raise RuntimeError(f"Failed to run nmap: {e}")

    # nmap returncodes: 0 ok, 1 some hosts down but XML may be present
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"nmap failed (rc={proc.returncode}): {proc.stderr.strip()}")

    if not proc.stdout.strip():
        raise RuntimeError(f"nmap produced no XML output. stderr: {proc.stderr.strip()}")

    return proc.stdout

def _parse_scripts(elem):
    """Parse <script> elements under hostscript or portscript into list of dicts."""
    out = []
    for script in elem.findall("script"):
        out.append({
            "id": script.get("id"),
            "output": (script.get("output") or "").strip()
        })
    return out

def parse_nmap_ports_and_scripts(xml_text: str) -> Dict:
    """
    Returns dict {
      "hosts": [
         {
           "ip": "1.2.3.4",
           "ports": [ {port, protocol, state, service, product, version, port_scripts: [...] }, ... ],
           "host_scripts": [ {id, output}, ... ]
         }, ...
      ]
    }
    """
    root = ET.fromstring(xml_text)
    hosts_out = []
    for host in root.findall("host"):
        # get ipv4 or ipv6 address
        addr = None
        for a in host.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr")
                break
        host_scripts = []
        hs = host.find("hostscript")
        if hs is not None:
            host_scripts = _parse_scripts(hs)

        ports_out = []
        ports = host.find("ports")
        if ports is not None:
            for port in ports.findall("port"):
                try:
                    portid = int(port.get("portid"))
                except Exception:
                    continue
                protocol = port.get("protocol")
                state_elem = port.find("state")
                state = state_elem.get("state") if state_elem is not None else "unknown"
                service_elem = port.find("service")
                service = service_elem.get("name") if service_elem is not None and "name" in service_elem.attrib else "unknown"
                product = service_elem.get("product") if service_elem is not None and "product" in service_elem.attrib else ""
                version = service_elem.get("version") if service_elem is not None and "version" in service_elem.attrib else ""

                # parse scripts under this port (if any)
                port_scripts = []
                ps = port.find("script")
                # Note: NSE script output for ports may appear as multiple <script> directly under port or under <port>/<script>
                port_scripts = _parse_scripts(port)

                ports_out.append({
                    "port": portid,
                    "protocol": protocol,
                    "state": state,
                    "service": service,
                    "product": product,
                    "version": version,
                    "port_scripts": port_scripts
                })

        hosts_out.append({
            "ip": addr or "unknown",
            "host_scripts": host_scripts,
            "ports": ports_out
        })
    return {"hosts": hosts_out}

def nmap_scan_with_scripts(target: str, start: int = 1, end: int = 1000, extra_args: str = "") -> Dict:
    """
    Runs nmap, returns parsed dict with hosts -> ports and scripts.
    Example extra_args to run vuln scripts: "--script vuln -sV"
    """
    ports_range = f"{start}-{end}"
    xml = run_nmap_xml(target, ports=ports_range, extra_args=extra_args)
    return parse_nmap_ports_and_scripts(xml)
