"""
Script to create an admin user in the database
Run: python create_admin.py
"""

import sys
sys.path.insert(0, '.')

from app import app, db
from models.database import User
from werkzeug.security import generate_password_hash
import uuid

with app.app_context():
    # Check if admin exists
    existing_admin = User.query.filter_by(username='admin').first()
    if existing_admin:
        print("❌ User 'admin' already exists")
        print(f"   Email: {existing_admin.email}")
        print(f"   Role: {existing_admin.role}")
        sys.exit(1)
    
    # Create admin user
    admin = User(
        id=str(uuid.uuid4()),
        username='admin',
        email='admin@example.com',
        password=generate_password_hash('Admin123!@'),
        role='admin',
        can_create_scans=True,
        can_schedule_scans=True,
        can_view_all_scans=True,
        can_manage_users=True,
        can_export_reports=True,
        is_active=True
    )
    
    db.session.add(admin)
    db.session.commit()
    
    print("✅ Admin user created successfully!")
    print()
    print("   👤 Admin Credentials:")
    print("   ─────────────────────────")
    print("   Username: admin")
    print("   Password: Admin123!@")
    print("   Role:     admin")
    print()
    print("   🔐 Admin has all permissions:")
    print("      • Create scans")
    print("      • Schedule scans")
    print("      • View all scans")
    print("      • Manage users")
    print("      • Export reports")
    print()
    print("   Next: Go to http://localhost:5173 and login")
