"""
Database Models
===============
SQLAlchemy ORM models, extended for User Authentication (v3.0).
"""

from app import db
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


class User(UserMixin, db.Model):
    """
    User Model for Authentication
    """
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128))
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class ThreatLog(db.Model):
    """
    Threat Intelligence Log Entry

    Stores every analysis transaction for SIEM capabilities:
    - Real-time threat feed
    - Incident response queries
    - Model performance monitoring
    - Compliance audit trails
    """
    __tablename__ = 'threat_logs'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.String(50), nullable=False, index=True)
    scan_type = db.Column(db.String(20), nullable=False)  # URL or IMG
    input_data = db.Column(db.Text, nullable=False)
    result_status = db.Column(db.String(20), nullable=False, index=True)  # SAFE, MALICIOUS, etc.
    confidence_score = db.Column(db.Float, nullable=False)
    analysis_method = db.Column(db.String(50), nullable=True)  # Heuristic, Neural, Reputation
    whois_info = db.Column(db.Text, nullable=True)  # JSON metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ThreatLog {self.id}: {self.scan_type} - {self.result_status}>'

    def to_dict(self):
        """Convert model to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'timestamp': self.timestamp,
            'type': self.scan_type,
            'input': self.input_data,
            'status': self.result_status,
            'confidence': self.confidence_score,
            'method': self.analysis_method,
            'metadata': self.whois_info
        }
