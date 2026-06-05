from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token
from werkzeug.security import generate_password_hash, check_password_hash
from models.database import db, User
import uuid
import datetime

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "")

    if not username:
        return jsonify({"error": "Username required"}), 400
    
    # Check if username already exists
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username taken"}), 409
    
    # Auto-generate unique email if not provided
    if not email:
        # Generate unique email using username + uuid to avoid conflicts
        email = f"{username}_{uuid.uuid4().hex[:6]}@vulnscanner.local"
    else:
        # If email provided, check if it already exists
        if User.query.filter_by(email=email).first():
            return jsonify({"error": "Email taken"}), 409
    
    # Auto-generate password if not provided
    if not password:
        password = f"{username}_vuln_{uuid.uuid4().hex[:8]}"
    
    # Validate password length (minimum 8 characters)
    if len(password) < 8:
        password = f"{password}_{uuid.uuid4().hex[:4]}"

    try:
        user = User(
            id=str(uuid.uuid4()),
            username=username,
            email=email,
            password=generate_password_hash(password),
            role="user",
            is_active=True,
            is_approved=False,
            can_create_scans=True,
            can_export_reports=True
        )
        db.session.add(user)
        db.session.commit()

        token = create_access_token(identity=user.id, expires_delta=datetime.timedelta(hours=8))
        return jsonify({
            "token": token, 
            "user": user.to_dict(),
            "message": f"Successfully registered '{username}'"
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Registration failed: {str(e)}"}), 500


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({"error": "Invalid credentials"}), 401

    if not user.is_active:
        reason = user.ban_reason if user.ban_reason else "Unknown"
        return jsonify({"error": f"Account inactive. Reason: {reason}"}), 403

    user.last_login = datetime.datetime.utcnow()
    db.session.commit()

    token = create_access_token(identity=user.id, expires_delta=datetime.timedelta(hours=8))
    return jsonify({"token": token, "user": user.to_dict()}), 200


@auth_bp.route("/create-admin", methods=["POST"])
def create_admin():
    """
    Create first admin user (no auth required).
    Remove after initial setup.
    """
    # Only allow if no admins exist
    if User.query.filter_by(role="admin").first():
        return jsonify({"error": "Admin already exists. Remove this endpoint in production."}), 403

    data = request.json
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "")

    if not username or not email or not password:
        return jsonify({"error": "All fields required"}), 400

    try:
        user = User(
            id=str(uuid.uuid4()),
            username=username,
            email=email,
            password=generate_password_hash(password),
            role="admin",
            is_active=True,
            is_approved=True,
            can_create_scans=True,
            can_schedule_scans=True,
            can_view_all_scans=True,
            can_manage_users=True,
            can_export_reports=True
        )
        db.session.add(user)
        db.session.commit()

        token = create_access_token(identity=user.id, expires_delta=datetime.timedelta(hours=8))
        return jsonify({"message": "Admin created", "token": token, "user": user.to_dict()}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Admin creation failed: {str(e)}"}), 500