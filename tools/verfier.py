# tools/verifier.py
# Verifies that patches took effect by rescanning and comparing results

from . import local_ip_scanner, public_ip_scanner
from .test_port import test_port_usability
from .vulnerability_scan import check_vulnerable_ports
from .scan_result import save_scan_results
from app.controller import analyze_ports

import ipaddress
from concurrent.futures import ThreadPoolExecutor

def verify_patches(previous_results):
    """
    Re-scan and compare results against pre-patch scan.
    Returns a report of fixed vs still-open vulnerabilities.
    """
    new_results = {"local": [], "public": []}
    fixed = []
    remaining = []

    # Local rescan
    for device in previous_results.get("local", []):
        ip = device["ip"]
        ports = local_ip_scanner.scan_ports(ip, 1, 1000)
        analyzed = analyze_ports(ports)

        # add usability + vulnerability check
        for port_info in analyzed:
            port_info["usability"] = test_port_usability(ip, port_info["port"])
        vuln_results = check_vulnerable_ports(ip, ports)
        for port, status in vuln_results.items():
            port_info = next((p for p in analyzed if p["port"] == port), None)
            if port_info:
                port_info["vulnerability_status"] = status

        new_results["local"].append({"ip": ip, "ports": analyzed})

        # Compare old vs new
        old_ports = {p["port"]: p for p in device["ports"]}
        for new_p in analyzed:
            port = new_p["port"]
            if port in old_ports:
                if old_ports[port]["risk"] != "Low" and new_p["usability"] == "N/A":
                    fixed.append(f"Port {port} on {ip} (Service {old_ports[port]['service']}) → FIXED")
                else:
                    remaining.append(f"Port {port} on {ip} (Service {new_p['service']}) → STILL OPEN")

    # Public rescan
    old_public = previous_results.get("public", {})
    if old_public:
        ip = old_public["ip"]
        ports = public_ip_scanner.scan_ports(ip, 1, 6000, threads=50)
        analyzed_pub = analyze_ports(ports)
        for port_info in analyzed_pub:
            port_info["usability"] = test_port_usability(ip, port_info["port"])
        vuln_results_pub = check_vulnerable_ports(ip, ports)
        for port, status in vuln_results_pub.items():
            port_info = next((p for p in analyzed_pub if p["port"] == port), None)
            if port_info:
                port_info["vulnerability_status"] = status

        new_results["public"] = {"ip": ip, "ports": analyzed_pub}

        old_ports = {p["port"]: p for p in old_public["ports"]}
        for new_p in analyzed_pub:
            port = new_p["port"]
            if port in old_ports:
                if old_ports[port]["risk"] != "Low" and new_p["usability"] == "N/A":
                    fixed.append(f"Port {port} on PUBLIC {ip} (Service {old_ports[port]['service']}) → FIXED")
                else:
                    remaining.append(f"Port {port} on PUBLIC {ip} (Service {new_p['service']}) → STILL OPEN")

    # Save results
    save_scan_results("verify_scan", new_results)

    return {
        "fixed": fixed,
        "remaining": remaining,
        "new_scan": new_results
    }
