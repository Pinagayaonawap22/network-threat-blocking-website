from flask import Blueprint, render_template, request, jsonify
from . import db    
from tools.system_scanner import get_system_info, get_system_metrics
from tools.verfier import verify_patches
import socket   
import subprocess
from .controller import deep_scan_all   # ✅ import the full scan function
from tools.patcher import apply_patches
from datetime import datetime
import requests
from tools.scan_result import get_last_scan
import ipaddress
from app.models import Threat, BlockLog
main = Blueprint('main', __name__)

@main.route('/')
def dashboard():
    return render_template('dashboard.html')

# Add a new threat
@main.route('/threats', methods=['POST'])
def add_threat():
    data = request.get_json()
    new_threat = Threat(
        name=data['name'],
        description=data['description'],
        severity=data['severity']
    )
    db.session.add(new_threat)
    db.session.commit()
    return jsonify({'message': 'Threat added successfully!'}), 201

# Update an existing threat
@main.route('/threats/<int:id>', methods=['PUT'])
def update_threat(id):
    threat = Threat.query.get_or_404(id)
    data = request.get_json()

    threat.name = data.get('name', threat.name)
    threat.description = data.get('description', threat.description)
    threat.severity = data.get('severity', threat.severity)

    db.session.commit()
    return jsonify({'message': f'Threat {id} updated successfully!'})

# Delete a threat
@main.route('/threats/<int:id>', methods=['DELETE'])
def delete_threat(id):
    threat = Threat.query.get_or_404(id)
    db.session.delete(threat)
    db.session.commit()
    return jsonify({'message': f'Threat {id} deleted successfully!'})

@main.route('/threats', methods=['GET'])
def get_threats():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)

    pagination = Threat.query.paginate(page=page, per_page=per_page, error_out=False)
    threats = pagination.items

    response = {
        'threats': [{
            'id': threat.id,
            'name': threat.name,
            'description': threat.description,
            'severity': threat.severity
        } for threat in threats],
        'total': pagination.total,
        'page': pagination.page,
        'per_page': pagination.per_page,
        'pages': pagination.pages
    }

    return jsonify(response)

@main.route('/deep_scan', methods=['GET'])
def deep_scan_route():
    try:
        scan_results = deep_scan_all()
        return jsonify({"message": "Scan completed", "local_scan": scan_results["local"], "public_scan": scan_results["public"]}), 200
    except Exception as e:
        LOG.exception("deep_scan exception")
        return jsonify({"error": str(e)}), 500


@main.route('/apply_patches', methods=['POST'])
def apply_patches_route():
    try:
        scan_results = deep_scan_all()
        actions = apply_patches(scan_results, simulate=True)  # Change to False to actually run
        return jsonify({
            "message": "Patching process completed.",
            "actions": actions
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@main.route('/verify_patches', methods=['POST'])
def verify_patches_route():
    try:
        old_scan = deep_scan_all()  # latest results before patching
        verification = verify_patches(old_scan)
        return jsonify({
            "message": "Verification completed.",
            "fixed": verification["fixed"],
            "remaining": verification["remaining"],
            "new_scan": verification["new_scan"]
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def geolocate_ip(ip):
    try:
        if ipaddress.ip_address(ip).is_private:
            return {
                "lat": 0,
                "lon": 0,
                "country": "Local Network",
                "city": ""
            }
        resp = requests.get(f"http://ip-api.com/json/{ip}").json()
        if resp["status"] == "success":
            return {
                "lat": resp["lat"],
                "lon": resp["lon"],
                "country": resp["country"],
                "city": resp.get("city", ""),
            }
    except:
        pass
    return {"lat": 0, "lon": 0, "country": "Unknown", "city": ""}

@main.route("/api/threats")
def api_threats():
    last = get_last_scan()
    if not last:
        return jsonify([])

    scan_data = last["result"]
    threats = []

    # Local devices
    for device in scan_data.get("local", []):
        ip = device["ip"]
        for port in device["ports"]:
            if port.get("state") == "open":
                geo = geolocate_ip(ip)
                threats.append({
                    "ip": ip,
                    "port": port["port"],
                    "risk": port.get("risk", "Unknown"),
                    "service": port.get("service", "Unknown"),
                    **geo
                })

    # Public device
    public = scan_data.get("public", {})
    if "ports" in public:
        for port in public["ports"]:
            if port.get("state") == "open":
                geo = geolocate_ip(public["ip"])
                threats.append({
                    "ip": public["ip"],
                    "port": port["port"],
                    "risk": port.get("risk", "Unknown"),
                    "service": port.get("service", "Unknown"),
                    **geo
                })

    return jsonify(threats)

@main.route("/api/blocks")
def api_blocks():
    # latest 100 blocks
    blocks = BlockLog.query.order_by(BlockLog.timestamp.desc()).limit(100).all()
    return jsonify([b.to_dict() for b in blocks])

@main.route("/api/stats")
def api_stats():
    # Example queries – adjust to your models
    from app.models import Threat, BlockLog

    critical_threats = Threat.query.filter(Threat.severity.in_(["High", "Critical"])).count()
    blocked_ips = BlockLog.query.count()
    pending_review = Threat.query.filter_by(status="Pending").count()

    stats = {
        "critical_threats": critical_threats,
        "blocked_ips": blocked_ips,
        "pending_review": pending_review,
        "system_health": "98.7%"  # or calculate uptime if you track it
    }
    return jsonify(stats)

@main.route("/api/system")
def api_system():
    return jsonify(get_system_info())

@main.route("/api/system_metrics")
def api_system_metrics():
    return jsonify(get_system_metrics())