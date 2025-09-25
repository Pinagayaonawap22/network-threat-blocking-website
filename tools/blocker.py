# tools/blocker.py
import subprocess
import platform
import logging
from app import db
from app.models import BlockLog

LOG = logging.getLogger(__name__)

def block_ip_os(ip: str, simulate=True):
    """
    Execute OS-level commands to block IP.
    simulate=True -> return command(s) that would be executed, no harm.
    Returns dict with status and commands.
    """
    system = platform.system().lower()
    actions = []
    if system == "windows":
        # Windows blocking via netsh (requires admin)
        cmd = f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}'
        actions.append(cmd)
    else:
        # Linux / Mac *nix: try ufw if exists else iptables
        # ufw: sudo ufw insert 1 deny from <ip> to any
        actions.append(f"ufw insert 1 deny from {ip} to any")  # if ufw is available
        actions.append(f"iptables -I INPUT -s {ip} -j DROP")    # fallback iptables
    results = {"ip": ip, "simulate": simulate, "commands": actions, "applied": []}

    if simulate:
        LOG.info("Simulating block for %s: %s", ip, actions)
        return results

    for cmd in actions:
        try:
            # Use shell=True because commands include shell syntax; ensure trusted inputs or sanitize ip
            subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            results["applied"].append({"cmd": cmd, "ok": True})
        except subprocess.CalledProcessError as e:
            LOG.exception("Failed to run: %s", cmd)
            results["applied"].append({"cmd": cmd, "ok": False, "err": e.stderr.decode() if hasattr(e, 'stderr') else str(e)})
        except Exception as e:
            LOG.exception("Unexpected error running: %s", cmd)
            results["applied"].append({"cmd": cmd, "ok": False, "err": str(e)})
    return results

def record_block_in_db(ip: str, action: str, risk: str = None, reason: str = None, applied_by: str = "system"):
    """
    Insert BlockLog entry and return the record dict.
    """
    bl = BlockLog(ip=ip, action=action, risk=risk or "Unknown", reason=reason or "", applied_by=applied_by)
    db.session.add(bl)
    db.session.commit()
    return bl.to_dict()
