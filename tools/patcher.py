
import subprocess

PATCH_ACTIONS = {
    "HTTP": {
        "risk": "Medium",
        "command": "ufw deny 80",  # Example firewall rule
        "note": "Redirect HTTP to HTTPS."
    },
    "NetBIOS": {
        "risk": "High",
        "command": "systemctl stop nmb && systemctl disable nmb",
        "note": "Disable NetBIOS service."
    },
    "SMB": {
        "risk": "High",
        "command": "ufw deny 445",
        "note": "Block SMB to prevent ransomware exploitation."
    },
    "RPC": {
        "risk": "High",
        "command": "ufw deny 135",
        "note": "Block RPC from external access."
    },
    "DNS": {
        "risk": "Medium",
        "command": "ufw deny 53",
        "note": "Restrict open DNS resolvers."
    }
}

def apply_patches(scan_results, simulate=True):
    """
    Apply system hardening patches based on scan results.
    If simulate=True, only prints what would be executed.
    """
    actions_taken = []

    for device in scan_results.get("local", []):
        for port_info in device.get("ports", []):
            service = port_info.get("service")
            if service in PATCH_ACTIONS:
                action = PATCH_ACTIONS[service]
                if simulate:
                    actions_taken.append(f"[SIMULATED] {action['command']}  # {action['note']}")
                else:
                    try:
                        subprocess.run(action["command"], shell=True, check=True)
                        actions_taken.append(f"[APPLIED] {action['command']}  # {action['note']}")
                    except subprocess.CalledProcessError as e:
                        actions_taken.append(f"[FAILED] {action['command']} - {str(e)}")

    return actions_taken
