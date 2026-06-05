# VulnScanner Advanced Features Integration Guide

Complete guide to add **RBAC**, **Scan Scheduling**, and **Vulnerability Reporting** to VulnScanner.

---

## 📋 Table of Contents

1. [Feature Overview](#feature-overview)
2. [Backend Integration](#backend-integration)
3. [Database Migration](#database-migration)
4. [Frontend Integration](#frontend-integration)
5. [Dependencies](#dependencies)
6. [Testing](#testing)
7. [Deployment](#deployment)

---

## 🎯 Feature Overview

### **1. Role-Based Access Control (RBAC)**

**Roles:**
- **Admin**: Full access, manage users, view all scans
- **Analyst**: Create/schedule scans, export reports
- **Auditor**: Read-only, access all scans, compliance tracking
- **User**: Basic user, create own scans

**Permissions Matrix:**

| Permission | Admin | Analyst | Auditor | User |
|-----------|-------|---------|---------|------|
| Create Scans | ✅ | ✅ | ❌ | ✅ |
| Schedule Scans | ✅ | ✅ | ❌ | ❌ |
| View All Scans | ✅ | ❌ | ✅ | ❌ |
| Manage Users | ✅ | ❌ | ❌ | ❌ |
| Export Reports | ✅ | ✅ | ✅ | ✅ |

---

### **2. Scan Scheduling**

**Features:**
- Schedule scans: Daily, Weekly, Monthly
- Automatic execution at scheduled time
- Email notifications on critical findings
- Scan history tracking

**API Endpoints:**
```
POST   /api/scheduled-scans              # Create schedule
GET    /api/scheduled-scans              # List user's schedules
PATCH  /api/scheduled-scans/<id>         # Update schedule
DELETE /api/scheduled-scans/<id>         # Delete schedule
```

---

### **3. Vulnerability Reporting**

**Features:**
- Professional PDF reports
- HTML reports for quick viewing
- Risk statistics dashboard
- Export findings (CSV, JSON)
- Trending analysis

**API Endpoints:**
```
GET    /api/scan/<id>/report/pdf         # Download PDF report
GET    /api/scan/<id>/report/html        # View HTML report
GET    /api/reports/dashboard            # Get vulnerability stats
```

---

## 🔧 Backend Integration

### **Step 1: Update Database Models**

Replace your `models/database.py` with the new `enhanced_models.py`:

```bash
# Backup old models
cp backend/models/database.py backend/models/database.py.backup

# Copy new models
cp enhanced_models.py backend/models/database.py
```

**New Models Added:**
- `UserRole` enum (admin, analyst, auditor, user)
- `ScanFrequency` enum (daily, weekly, monthly)
- Enhanced `User` model with RBAC fields
- `ScheduledScan` model for scheduling
- Updated `Finding` model for reporting
- Updated `AuditLog` model

---

### **Step 2: Add Backend Routes**

Add these routes to your `backend/app.py`:

```python
# Copy from enhanced_backend_routes.py
# Add these imports at the top:

from functools import wraps
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
import uuid

# Add all the decorators, endpoints, and helper functions
# from enhanced_backend_routes.py
```

---

### **Step 3: Install Required Dependencies**

```bash
cd backend

# Install scheduling library
pip install APScheduler --break-system-packages

# Install PDF generation (already in requirements.txt)
pip install reportlab --break-system-packages

# Update requirements.txt
pip freeze > requirements.txt
```

**Updated requirements.txt should include:**
```
Flask==2.3.0
Flask-SQLAlchemy==3.0.0
Flask-JWT-Extended==4.4.0
APScheduler==3.10.0
reportlab==4.0.4
python-nmap==0.0.1
requests==2.31.0
```

---

### **Step 4: Database Migration**

Create a migration script to update the database:

```bash
# Backup existing database
cp backend/vulnscanner.db backend/vulnscanner.db.backup

# Create migration script
cat > backend/migrate_db.py << 'EOF'
from models.database import db, User, UserRole
from app import app

with app.app_context():
    # Create all new tables
    db.create_all()
    
    # Update existing users to have default role
    users = User.query.all()
    for user in users:
        if not user.role:
            user.role = UserRole.USER.value
            user.can_create_scans = True
            user.can_export_reports = True
        
        # Set permissions based on role
        if user.role == UserRole.ADMIN.value:
            user.can_manage_users = True
            user.can_view_all_scans = True
            user.can_schedule_scans = True
        
        db.session.add(user)
    
    db.session.commit()
    print("✅ Database migration complete!")
EOF

python migrate_db.py
```

---

## 🗄️ Database Migration

### **SQL Migrations** (Alternative Method)

If you prefer raw SQL:

```sql
-- Add RBAC columns to users table
ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT 'user';
ALTER TABLE users ADD COLUMN can_create_scans BOOLEAN DEFAULT 1;
ALTER TABLE users ADD COLUMN can_schedule_scans BOOLEAN DEFAULT 0;
ALTER TABLE users ADD COLUMN can_view_all_scans BOOLEAN DEFAULT 0;
ALTER TABLE users ADD COLUMN can_manage_users BOOLEAN DEFAULT 0;
ALTER TABLE users ADD COLUMN can_export_reports BOOLEAN DEFAULT 1;

-- Create scheduled_scans table
CREATE TABLE IF NOT EXISTS scheduled_scans (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    target VARCHAR(255) NOT NULL,
    profile VARCHAR(50),
    frequency VARCHAR(20),
    next_run DATETIME,
    last_run DATETIME,
    is_active BOOLEAN DEFAULT 1,
    run_exploits BOOLEAN DEFAULT 0,
    modules JSON,
    notify_email VARCHAR(120),
    notify_on_critical BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

-- Update findings table
ALTER TABLE findings ADD COLUMN resolved_at DATETIME;
ALTER TABLE findings ADD COLUMN status VARCHAR(20) DEFAULT 'open';
ALTER TABLE findings ADD COLUMN remediation TEXT;
```

---

## 🎨 Frontend Integration

### **Step 1: Replace AdminPanel**

```bash
# Backup old AdminPanel
cp frontend/src/AdminPanel.jsx frontend/src/AdminPanel.jsx.backup

# Copy new AdminPanel
cp EnhancedAdminPanel.jsx frontend/src/AdminPanel.jsx
```

### **Step 2: Update Main App Component**

In your `frontend/src/App.jsx`, add the new routes:

```jsx
import EnhancedAdminPanel from "./EnhancedAdminPanel";

// Add to your main app:
{tab === "admin" && <EnhancedAdminPanel token={token} user={user} />}

// Update tab buttons to show Admin tab for admin users:
{user?.role === "admin" && (
  <button onClick={() => setTab("admin")} style={{...}}>
    ⚙️ Admin Panel
  </button>
)}
```

### **Step 3: Add New Components**

Create three new components in `frontend/src/`:

1. **RBACManager.jsx** - User role management
2. **ScanScheduler.jsx** - Schedule scans
3. **ReportGenerator.jsx** - Generate reports

(These are already included in EnhancedAdminPanel.jsx as sub-components)

---

## 📦 Dependencies

### **Backend Dependencies**

```bash
pip install -r requirements.txt
```

**requirements.txt:**
```
Flask==2.3.0
Flask-SQLAlchemy==3.0.0
Flask-JWT-Extended==4.4.0
python-nmap==0.0.1
requests==2.31.0
paramiko==3.2.0
APScheduler==3.10.0
reportlab==4.0.4
```

### **Frontend Dependencies**

Already installed in your React project:
- React 18+
- React Router (for navigation)

---

## 🧪 Testing

### **1. Test RBAC**

```bash
# Create users with different roles
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"analyst1","email":"analyst@test.com","password":"Test12345"}'

# Get token
TOKEN=$(curl -s -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"analyst1","password":"Test12345"}' | grep -o '"token":"[^"]*' | cut -d'"' -f4)

# Admin changes role to analyst
curl -X PATCH http://localhost:5000/api/admin/users/<user_id>/role \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -d '{"role":"analyst"}'

# Verify analyst can't manage users
curl -X GET http://localhost:5000/api/admin/users \
  -H "Authorization: Bearer $TOKEN"
# Should return 403 Forbidden
```

### **2. Test Scheduling**

```bash
# Create scheduled scan
curl -X POST http://localhost:5000/api/scheduled-scans \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "name":"Weekly Server Scan",
    "target":"192.168.1.1",
    "frequency":"weekly",
    "profile":"quick"
  }'

# List scheduled scans
curl -X GET http://localhost:5000/api/scheduled-scans \
  -H "Authorization: Bearer $TOKEN"
```

### **3. Test Reporting**

```bash
# Get vulnerability stats
curl -X GET http://localhost:5000/api/reports/dashboard \
  -H "Authorization: Bearer $TOKEN"

# Download PDF report
curl -X GET http://localhost:5000/api/scan/<scan_id>/report/pdf \
  -H "Authorization: Bearer $TOKEN" \
  -o report.pdf
```

---

## 🚀 Deployment Checklist

- [ ] **Database**: Migrated to new schema
- [ ] **Backend**: All new routes added and tested
- [ ] **Frontend**: Admin panel updated with new tabs
- [ ] **Dependencies**: All packages installed
- [ ] **RBAC**: Roles assigned to existing users
- [ ] **Scheduler**: APScheduler running in background
- [ ] **Email**: SMTP configured (optional)
- [ ] **Tests**: All features tested locally
- [ ] **Security**: JWT tokens updated (if needed)
- [ ] **Logging**: Audit logs working
- [ ] **Backups**: Database backed up
- [ ] **Documentation**: Team trained on new features

---

## 📚 Usage Examples

### **Admin: Change User Role to Analyst**

1. Login as Admin
2. Go to **⚙️ Admin Panel** → **👥 RBAC**
3. Find user "john_doe"
4. Click "Change Role"
5. Select "Analyst"
6. Click "Update"

### **Analyst: Schedule Daily Scan**

1. Go to **⚙️ Admin Panel** → **⏰ Scheduling**
2. Enter: Name: "Daily API Scan", Target: "api.example.com"
3. Select Frequency: "Daily"
4. Click "✅ Schedule Scan"
5. Scan will run daily at same time

### **Auditor: View Vulnerability Report**

1. Login as Auditor
2. Go to **📊 Results** or **⚙️ Admin Panel** → **📊 Reports**
3. View risk statistics and critical findings
4. Click "📄 Export as PDF" to download
5. Share with management

---

## 🔒 Security Notes

1. **Role Validation**: All endpoints validate user role before executing
2. **Token Expiry**: JWT tokens expire after 8 hours
3. **Audit Logging**: Every action logged with user, timestamp, IP
4. **Permission Checks**: Users can't access other users' scans (unless Admin/Auditor)
5. **Password Hashing**: All passwords hashed with bcrypt

---

## 🐛 Troubleshooting

### **Issue: "No role_required decorator"**
**Solution**: Make sure all imports are at top of `app.py`

### **Issue: "APScheduler not installed"**
**Solution**: 
```bash
pip install APScheduler --break-system-packages
```

### **Issue: "Database locked" error**
**Solution**: 
```bash
rm backend/vulnscanner.db
python backend/app.py
```

### **Issue: Scans not scheduling**
**Solution**: Check APScheduler logs, ensure `schedule.run()` is called in Flask app

---

## 📞 Support

For issues, check:
1. Backend console for errors
2. Browser F12 console for frontend errors
3. Database logs for query errors
4. Audit logs for action history

---

## 📄 License

Same as VulnScanner

---

**Version**: 1.0  
**Last Updated**: May 2026  
**Status**: Production Ready