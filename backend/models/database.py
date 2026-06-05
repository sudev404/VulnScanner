"""
Enhanced Database Models with RBAC and Scheduling
"""
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from enum import Enum

db = SQLAlchemy()

class UserRole(Enum):
    """User roles for RBAC"""
    ADMIN = "admin"          # Full access
    ANALYST = "analyst"      # Can run scans, view results
    AUDITOR = "auditor"      # Read-only access
    USER = "user"            # Basic user

class ScanFrequency(Enum):
    """Scheduled scan frequency"""
    ONCE = "once"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"

# ════════════════════════════════════════════════════════════════════════════
# USER MODEL - Enhanced with roles
# ════════════════════════════════════════════════════════════════════════════

class User(db.Model):
    __tablename__ = "users"
    
    id = db.Column(db.String(36), primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    
    # RBAC Fields
    role = db.Column(db.String(20), default=UserRole.USER.value)  # admin, analyst, auditor, user
    is_active = db.Column(db.Boolean, default=True)
    is_approved = db.Column(db.Boolean, default=False)
    
    # Permissions
    can_create_scans = db.Column(db.Boolean, default=True)
    can_schedule_scans = db.Column(db.Boolean, default=False)
    can_view_all_scans = db.Column(db.Boolean, default=False)
    can_manage_users = db.Column(db.Boolean, default=False)
    can_export_reports = db.Column(db.Boolean, default=True)
    
    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    ban_reason = db.Column(db.String(255))
    
    # Relationships
    scans = db.relationship("Scan", backref="user", lazy=True, cascade="all, delete-orphan")
    scheduled_scans = db.relationship("ScheduledScan", backref="user", lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        """Convert user to dictionary"""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "is_approved": self.is_approved,
            "is_admin": self.role == "admin",  # For backward compatibility
            "permissions": {
                "create_scans": self.can_create_scans,
                "schedule_scans": self.can_schedule_scans,
                "view_all_scans": self.can_view_all_scans,
                "manage_users": self.can_manage_users,
                "export_reports": self.can_export_reports
            },
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None
        }

# ════════════════════════════════════════════════════════════════════════════
# SCAN MODEL - With metadata for reporting
# ════════════════════════════════════════════════════════════════════════════

class Scan(db.Model):
    __tablename__ = "scans"
    
    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False)
    
    # Scan Details
    target = db.Column(db.String(255), nullable=False)
    profile = db.Column(db.String(50), default="quick")  # quick, full, stealth, web
    status = db.Column(db.String(50), default="pending")  # pending, running, completed, failed
    
    # Results
    risk_score = db.Column(db.Integer, default=0)
    risk_level = db.Column(db.String(20))  # Critical, High, Medium, Low
    
    # Execution
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    duration_seconds = db.Column(db.Integer)
    
    # Config
    run_exploits = db.Column(db.Boolean, default=False)
    consent_given = db.Column(db.Boolean, default=False)
    source_ip = db.Column(db.String(45))
    
    # For reports
    scheduled_scan_id = db.Column(db.String(36), db.ForeignKey("scheduled_scans.id"))
    
    # Relationships
    findings = db.relationship("Finding", backref="scan", lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        """Convert scan to dictionary"""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "target": self.target,
            "profile": self.profile,
            "status": self.status,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "run_exploits": self.run_exploits,
            "consent_given": self.consent_given,
            "source_ip": self.source_ip,
            "findings_count": len(self.findings)
        }

# ════════════════════════════════════════════════════════════════════════════
# FINDING MODEL
# ════════════════════════════════════════════════════════════════════════════

class Finding(db.Model):
    __tablename__ = "findings"
    
    id = db.Column(db.String(36), primary_key=True)
    scan_id = db.Column(db.String(36), db.ForeignKey("scans.id"), nullable=False)
    
    # Finding Details
    category = db.Column(db.String(50))  # Port, Service, CVE, Web, OSINT
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20))  # Critical, High, Medium, Low, Info
    cvss_score = db.Column(db.Float)
    cve_id = db.Column(db.String(20))
    
    # Details
    port = db.Column(db.Integer)
    service = db.Column(db.String(100))
    evidence = db.Column(db.Text)
    remediation = db.Column(db.Text)
    
    # Metadata
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    status = db.Column(db.String(20), default="open")  # open, resolved, false_positive

    def to_dict(self):
        """Convert finding to dictionary"""
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cve_id": self.cve_id,
            "port": self.port,
            "service": self.service,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "status": self.status
        }

# ════════════════════════════════════════════════════════════════════════════
# SCHEDULED SCAN MODEL
# ════════════════════════════════════════════════════════════════════════════

class ScheduledScan(db.Model):
    __tablename__ = "scheduled_scans"
    
    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"), nullable=False)
    
    # Schedule Details
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    target = db.Column(db.String(255), nullable=False)
    profile = db.Column(db.String(50), default="quick")
    
    # Frequency
    frequency = db.Column(db.String(20), default="weekly")  # once, daily, weekly, monthly
    next_run = db.Column(db.DateTime)
    last_run = db.Column(db.DateTime)
    
    # Config
    is_active = db.Column(db.Boolean, default=True)
    run_exploits = db.Column(db.Boolean, default=False)
    modules = db.Column(db.JSON, default=lambda: ["ports", "services", "cve"])
    
    # Notifications
    notify_email = db.Column(db.String(120))
    notify_on_critical = db.Column(db.Boolean, default=True)
    notify_on_findings = db.Column(db.Boolean, default=False)
    
    # Metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    scans = db.relationship("Scan", backref="scheduled_scan", lazy=True)

    def to_dict(self):
        """Convert scheduled scan to dictionary"""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "name": self.name,
            "description": self.description,
            "target": self.target,
            "profile": self.profile,
            "frequency": self.frequency,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "is_active": self.is_active,
            "run_exploits": self.run_exploits,
            "modules": self.modules,
            "notify_email": self.notify_email,
            "notify_on_critical": self.notify_on_critical,
            "notify_on_findings": self.notify_on_findings,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }

# ════════════════════════════════════════════════════════════════════════════
# AUDIT LOG MODEL
# ════════════════════════════════════════════════════════════════════════════

class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    
    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.String(36), db.ForeignKey("users.id"))
    
    # Action Details
    action = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(50))  # user, scan, finding, schedule
    resource_id = db.Column(db.String(36))
    
    # Details
    details = db.Column(db.JSON)
    success = db.Column(db.Boolean, default=True)
    error_message = db.Column(db.Text)
    
    # Metadata
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))

# ════════════════════════════════════════════════════════════════════════════
# ADMIN CONFIG MODEL
# ════════════════════════════════════════════════════════════════════════════

class AdminConfig(db.Model):
    __tablename__ = "admin_config"
    
    id = db.Column(db.Integer, primary_key=True, default=1)
    
    # Scan Limits
    max_concurrent_scans = db.Column(db.Integer, default=5)
    scan_timeout_minutes = db.Column(db.Integer, default=30)
    require_approval = db.Column(db.Boolean, default=False)
    
    # Security
    whitelist_enabled = db.Column(db.Boolean, default=False)
    whitelist_ips = db.Column(db.JSON, default=lambda: [])
    blacklist_enabled = db.Column(db.Boolean, default=False)
    blacklist_ips = db.Column(db.JSON, default=lambda: [])
    
    # RBAC Defaults
    auto_approve_users = db.Column(db.Boolean, default=False)
    default_user_role = db.Column(db.String(20), default=UserRole.USER.value)
    
    # Email/Notifications
    smtp_enabled = db.Column(db.Boolean, default=False)
    smtp_server = db.Column(db.String(255))
    smtp_port = db.Column(db.Integer, default=587)
    smtp_email = db.Column(db.String(120))
    
    # Updated
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        """Convert admin config to dictionary"""
        return {
            "id": self.id,
            "max_concurrent_scans": self.max_concurrent_scans,
            "scan_timeout_minutes": self.scan_timeout_minutes,
            "require_approval": self.require_approval,
            "whitelist_enabled": self.whitelist_enabled,
            "whitelist_ips": self.whitelist_ips,
            "blacklist_enabled": self.blacklist_enabled,
            "blacklist_ips": self.blacklist_ips,
            "auto_approve_users": self.auto_approve_users,
            "default_user_role": self.default_user_role,
            "smtp_enabled": self.smtp_enabled,
            "smtp_server": self.smtp_server,
            "smtp_port": self.smtp_port,
            "smtp_email": self.smtp_email,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }