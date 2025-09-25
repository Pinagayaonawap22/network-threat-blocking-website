# controller.py
import logging
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
from flask import jsonify
from tools import nmap_scanner, local_ip_scanner, public_ip_scanner
from tools.nmap_scanner import nmap_scan_with_scripts
from tools.test_port import test_port_usability
from tools.vulnerability_scan import check_vulnerable_ports
from tools.scan_result import save_scan_results, save_threats
from tools.blocker import block_ip_os, record_block_in_db

LOG = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


# --- Risk mapping (keep/extend as needed) ---
PORT_RISKS = {
    22: {"service": "SSH", "risk": "Medium", "advice": "Use strong passwords or key-based authentication."},
    23: {"service": "Telnet", "risk": "High", "advice": "Avoid Telnet; use SSH instead."},
    25: {"service": "SMTP", "risk": "Medium", "advice": "Secure mail server with TLS and authentication."},
    53: {"service": "DNS", "risk": "Medium", "advice": "Prevent open DNS resolvers to avoid abuse."},
    80: {"service": "HTTP", "risk": "Medium", "advice": "Redirect HTTP to HTTPS."},
    110: {"service": "POP3", "risk": "Medium", "advice": "Use encrypted POP3S instead."},
    135: {"service": "RPC", "risk": "High", "advice": "Block RPC from the internet."},
    139: {"service": "NetBIOS", "risk": "High", "advice": "Disable NetBIOS on public networks."},
    143: {"service": "IMAP", "risk": "Medium", "advice": "Use IMAPS instead."},
    443: {"service": "HTTPS", "risk": "Low", "advice": "Ensure SSL/TLS configuration is secure."},
    445: {"service": "SMB", "risk": "High", "advice": "Block SMB from public networks."},
    3389: {"service": "RDP", "risk": "High", "advice": "Restrict RDP access; use VPN."},
}


# --- Normalizers ---
def normalize_ports_from_nmap(nmap_ports):
    """Normalize list of raw nmap port dicts to consistent internal shape."""
    normalized = []
    for p in nmap_ports:
        normalized.append({
            "port": int(p.get("port")),
            "protocol": p.get("protocol", "tcp"),
            "state": p.get("state", "unknown"),
            "service": p.get("service", "unknown"),
            "product": p.get("product", ""),
            "version": p.get("version", ""),
            # preserve any port-level scripts from nmap parser
            "port_scripts": p.get("port_scripts", []),
        })
    return normalized


def normalize_ports_from_socket(ports_ints):
    """Convert fallback socket scanner results (list[int]) into nmap-like dicts."""
    return [{"port": int(p), "protocol": "tcp", "state": "open", "service": "unknown", "product": "", "version": "", "port_scripts": []} for p in ports_ints]


# --- Analysis ---
def analyze_ports(port_dicts):
    """
    Accepts list[dict] where each dict has at least 'port' and 'service'.
    Returns enriched list with risk/advice fields.
    """
    analyzed = []
    for p in port_dicts:
        port_num = int(p.get("port"))
        base = PORT_RISKS.get(port_num, {
            "service": p.get("service", "Unknown"),
            "risk": "Unknown",
            "advice": "No data available."
        })
        analyzed.append({
            "port": port_num,
            "state": p.get("state", "unknown"),
            "service": p.get("service", base["service"]),
            "product": p.get("product", ""),
            "version": p.get("version", ""),
            "risk": base["risk"],
            "advice": base["advice"],
            "port_scripts": p.get("port_scripts", []),  # may be empty
        })
    return analyzed


# --- Scanning helpers ---
def scan_host_with_fallback(target_ip, start=1, end=1000, extra_args=""):
    """
    Try nmap first; if it fails, fall back to socket scanner.
    Returns normalized list of port dicts.
    """
    try:
        nmap_ports = nmap_scanner.nmap_scan_ports(str(target_ip), start=start, end=end, extra_args=extra_args)
        return normalize_ports_from_nmap(nmap_ports)
    except Exception as e:
        LOG.warning("Nmap quick scan failed for %s (%s). Falling back to socket scan.", target_ip, e)
        try:
            ports_ints = local_ip_scanner.scan_ports(str(target_ip), start, end, threads=200)
            return normalize_ports_from_socket(ports_ints)
        except Exception as e2:
            LOG.exception("Socket fallback also failed for %s: %s", target_ip, e2)
            return []


# --- Main deep scan function ---
def deep_scan_all(concurrency_local=100, nmap_port_range=(1, 1000), do_nse_vuln_scan=True, simulate_block=True):
    """
    Perform local network and public IP scan, attach NSE script outputs when requested,
    optionally auto-log (and optionally apply) blocking actions for High/Critical risks.
    Returns results dict.
    """
    results = {"local": [], "public": {}}
    start_port, end_port = nmap_port_range

    lan_ip = local_ip_scanner.get_lan_ip()
    if lan_ip:
        network = ipaddress.ip_network(lan_ip + "/24", strict=False)
        devices_online = []

        LOG.info("Starting local host discovery on %s/24", lan_ip)
        hosts = list(network.hosts())

        with ThreadPoolExecutor(max_workers=concurrency_local) as executor:
            futures = {executor.submit(local_ip_scanner.is_host_alive, host): str(host) for host in hosts}
            for fut in as_completed(futures):
                ip = futures[fut]
                try:
                    alive = fut.result()
                except Exception:
                    LOG.exception("Host discovery error for %s", ip)
                    continue
                if not alive:
                    continue

                # For each live host, run scan (NSE vuln scan if enabled, otherwise quick scan)
                analyzed = []
                try:
                    LOG.info("Scanning host %s with ports %d-%d", ip, start_port, end_port)

                    if do_nse_vuln_scan:
                        # Run nmap with scripts; extra_args can include --script vuln -sV
                        try:
                            scan_result = nmap_scan_with_scripts(str(ip), start=start_port, end=end_port, extra_args="--script vuln -sV -T4")
                            host_entry = scan_result["hosts"][0] if scan_result["hosts"] else None
                            raw_ports = host_entry["ports"] if host_entry else []
                            port_dicts = normalize_ports_from_nmap(raw_ports)
                        except Exception as e:
                            LOG.exception("NSE vuln-scan failed for %s, falling back to quick scan: %s", ip, e)
                            port_dicts = scan_host_with_fallback(ip, start=start_port, end=end_port, extra_args="-T4 -sV")
                    else:
                        port_dicts = scan_host_with_fallback(ip, start=start_port, end=end_port, extra_args="-T4 -sV")

                    analyzed = analyze_ports(port_dicts)

                    # attach NSE port scripts into analyzed entries if present
                    if do_nse_vuln_scan and 'raw_ports' in locals():
                        for p in analyzed:
                            raw = next((r for r in raw_ports if r["port"] == p["port"]), None)
                            if raw:
                                p["port_scripts"] = raw.get("port_scripts", [])
                                # mark vulnerability status from NSE keywords
                                if any("vulnerable" in (s.get("output", "") or "").lower() for s in p["port_scripts"]):
                                    p["vulnerability_status"] = "⚠️ NSE reported possible vulnerability"
                                elif p["port_scripts"]:
                                    p["vulnerability_status"] = "NSE script output (no obvious 'vulnerable' keyword)"
                                else:
                                    p["vulnerability_status"] = p.get("vulnerability_status", "No NSE vuln detected")

                    # usability checks
                    for port_info in analyzed:
                        try:
                            port_info["usability"] = test_port_usability(str(ip), port_info["port"])
                        except Exception:
                            port_info["usability"] = "N/A"

                    # vulnerability map (existing rule-based checks)
                    try:
                        vuln_map = check_vulnerable_ports(str(ip), [p["port"] for p in analyzed])
                        for port, status in vuln_map.items():
                            pinfo = next((x for x in analyzed if x["port"] == port), None)
                            if pinfo:
                                pinfo["vulnerability_status"] = status
                            else:
                                analyzed.append({"port": port, "vulnerability_status": status})
                    except Exception:
                        LOG.exception("Vulnerability check failed for %s", ip)

                    # Add device to devices_online
                    devices_online.append({"ip": str(ip), "ports": analyzed})
                except Exception:
                    LOG.exception("Scanning failed for %s", ip)
                    # if scanning failed, ensure we do not reference analyzed if not set
                    analyzed = analyzed if isinstance(analyzed, list) else []

                # --- Auto-blocking logic (safe: simulated by default) ---
                for port_info in analyzed:
                    risk = port_info.get("risk", "Unknown")
                    if risk in ("High", "Critical"):
                        # validate ip string before running commands
                        try:
                            ipaddress.ip_address(ip)
                        except Exception:
                            LOG.warning("Invalid IP, skipping block: %s", ip)
                            continue

                        action = "Blocked" if risk == "Critical" else "Rate Limited"
                        # use simulate_block parameter
                        try:
                            block_result = block_ip_os(ip, simulate=simulate_block)
                        except Exception as e:
                            LOG.exception("Block command failed for %s: %s", ip, e)
                            block_result = {"ip": ip, "simulate": simulate_block, "commands": [], "applied": []}

                        try:
                            record = record_block_in_db(
                                ip=ip,
                                action=action,
                                risk=risk,
                                reason=f"Auto-block by scan: port {port_info['port']}"
                            )
                        except Exception:
                            LOG.exception("Failed to record block DB entry for %s", ip)
                            record = None

                        LOG.info("Auto-block recorded: %s; simulate_result: %s", record, block_result)
                        port_info["auto_block"] = {
                            "action": action,
                            "result": block_result,
                            "db": record
                        }

        results["local"] = devices_online
    else:
        LOG.warning("No LAN IP detected; skipping local scan.")

    # ---- Public scan ----
    public_ip = public_ip_scanner.get_public_ip()
    if public_ip:
        try:
            LOG.info("Scanning public IP %s", public_ip)
            if do_nse_vuln_scan:
                try:
                    scan_result_pub = nmap_scan_with_scripts(public_ip, start=start_port, end=6000, extra_args="--script vuln -sV -T4")
                    host_entry_pub = scan_result_pub["hosts"][0] if scan_result_pub["hosts"] else None
                    raw_ports_pub = host_entry_pub["ports"] if host_entry_pub else []
                    port_dicts_pub = normalize_ports_from_nmap(raw_ports_pub)
                except Exception as e:
                    LOG.exception("Public NSE vuln-scan failed for %s, falling back: %s", public_ip, e)
                    port_dicts_pub = scan_host_with_fallback(public_ip, start=start_port, end=6000, extra_args="-T4 -sV")
            else:
                port_dicts_pub = scan_host_with_fallback(public_ip, start=start_port, end=6000, extra_args="-T4 -sV")

            analyzed_pub = analyze_ports(port_dicts_pub)

            # attach NSE outputs for public ports
            if do_nse_vuln_scan and 'raw_ports_pub' in locals():
                for p in analyzed_pub:
                    raw = next((r for r in raw_ports_pub if r["port"] == p["port"]), None)
                    if raw:
                        p["port_scripts"] = raw.get("port_scripts", [])
                        if any("vulnerable" in (s.get("output", "") or "").lower() for s in p["port_scripts"]):
                            p["vulnerability_status"] = "⚠️ NSE reported possible vulnerability"
                        elif p["port_scripts"]:
                            p["vulnerability_status"] = "NSE script output (no obvious 'vulnerable' keyword)"
                        else:
                            p["vulnerability_status"] = p.get("vulnerability_status", "No NSE vuln detected")

            for port_info in analyzed_pub:
                try:
                    port_info["usability"] = test_port_usability(public_ip, port_info["port"])
                except Exception:
                    port_info["usability"] = "N/A"

            try:
                vuln_results_pub = check_vulnerable_ports(public_ip, [p["port"] for p in analyzed_pub])
                for port, status in vuln_results_pub.items():
                    pinfo = next((x for x in analyzed_pub if x["port"] == port), None)
                    if pinfo:
                        pinfo["vulnerability_status"] = status
                    else:
                        analyzed_pub.append({"port": port, "vulnerability_status": status})
            except Exception:
                LOG.exception("Vulnerability check failed for public IP %s", public_ip)

            results["public"] = {"ip": public_ip, "ports": analyzed_pub}
        except Exception:
            LOG.exception("Public IP scan failed for %s", public_ip)
    else:
        LOG.warning("No public IP detected; skipping public scan.")

    # Save results defensively
    try:
        save_scan_results("deep_scan", results)
        save_threats(results)
    except Exception:
        LOG.exception("Failed to save scan results")

    return results


# --- Flask route helper (call this from your route) ---
def deep_scan_route_handler():
    """
    Call this in your Flask route handler to perform a deep scan and return JSON.
    Example route:
      @main.route('/deep_scan', methods=['GET'])
      def deep_scan():
          return deep_scan_route_handler()
    """
    try:
        # do_nse_vuln_scan=True runs NSE vuln scripts (intrusive); toggle if needed
        results = deep_scan_all(do_nse_vuln_scan=True, simulate_block=True)
        return jsonify({
            "message": "Scan completed successfully",
            "local_scan": results.get("local", []),
            "public_scan": results.get("public", {})
        }), 200
    except Exception as e:
        tb = traceback.format_exc()
        LOG.error("deep_scan_all failed: %s\n%s", e, tb)
        # in dev return traceback; in production remove traceback content
        return jsonify({"error": str(e), "traceback": tb}), 500
