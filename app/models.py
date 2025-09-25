from . import db
from datetime import datetime
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)


class Threat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    description = db.Column(db.Text)
    severity = db.Column(db.String(50))
    status = db.Column(db.String(50), default="Pending")  # ✅ NEW COLUMN
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class ScanLog(db.Model):  # ✅ 
    __tablename__ = "scan_log"   # 👈 prevent conflict
    id = db.Column(db.Integer, primary_key=True)
    scan_type = db.Column(db.String(100), nullable=False)  
    result = db.Column(db.JSON, nullable=False)         
    timestamp = db.Column(db.DateTime, nullable=False)

    def __repr__(self):
        return f"<ScanLog {self.scan_type} @ {self.timestamp}>"

class BlockLog(db.Model):
    __tablename__ = 'block_logs'
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), nullable=False, index=True)  # IPv4/IPv6
    action = db.Column(db.String(64), nullable=False)  # Blocked, Rate Limited, Quarantined, etc.
    reason = db.Column(db.String(255), nullable=True)
    risk = db.Column(db.String(32), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    applied_by = db.Column(db.String(64), nullable=True)  # optional username or system tag

    def to_dict(self):
        return {
            "id": self.id,
            "ip": self.ip,
            "action": self.action,
            "reason": self.reason,
            "risk": self.risk,
            "timestamp": self.timestamp.isoformat()
        }