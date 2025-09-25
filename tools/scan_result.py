# tools/scan_result.py

from app import db
from app.models import ScanLog, Threat
from datetime import datetime

def save_scan_results(scan_type, scan_data):
    log = ScanLog(
        scan_type=scan_type,
        result=scan_data,
        timestamp=datetime.utcnow()
    )
    db.session.add(log)
    db.session.commit()
    return log.id

def get_latest_scan(limit=5):
    """Retrieve the latest scan results (default: 5 most recent)."""
    logs = ScanLog.query.order_by(ScanLog.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": log.id,
            "timestamp": log.timestamp,
            "scan_type": log.scan_type,
            "result": log.result
        }
        for log in logs
    ]

def get_last_scan():
    """Retrieve only the most recent scan result."""
    log = ScanLog.query.order_by(ScanLog.timestamp.desc()).first()
    if not log:
        return None
    return {
        "id": log.id,
        "timestamp": log.timestamp,
        "scan_type": log.scan_type,
        "result": log.result
    }

def extract_vulnerabilities(scan_data):
    """Flatten vulnerabilities from scan results for Threat model."""
    threats = []
    for device in scan_data.get("local", []):
        for port in device["ports"]:
            if "⚠️" in str(port.get("vulnerability_status", "")):
                threats.append({
                    "name": f"{port['service']} on {device['ip']}",
                    "description": f"Port {port['port']} shows {port['vulnerability_status']}",
                    "severity": port["risk"]
                })
    for port in scan_data.get("public", {}).get("ports", []):
        if "⚠️" in str(port.get("vulnerability_status", "")):
            threats.append({
                "name": f"{port['service']} on {scan_data['public']['ip']}",
                "description": f"Port {port['port']} shows {port['vulnerability_status']}",
                "severity": port["risk"]
            })
    return threats

def save_threats(scan_data):
    """Save extracted threats to Threat table."""
    threats = extract_vulnerabilities(scan_data)
    for t in threats:
        threat = Threat(
            name=t["name"],
            description=t["description"],
            severity=t["severity"]
        )
        db.session.add(threat)
    db.session.commit()
    return len(threats)
