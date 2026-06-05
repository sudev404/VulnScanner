# PostgreSQL Setup Guide for VulnScanner

This guide covers setting up PostgreSQL for production use with VulnScanner.

## Option 1: Using Docker (Recommended)

### Start PostgreSQL Container

```bash
docker run --name vulnscanner-postgres \
  -e POSTGRES_USER=vulnscanner \
  -e POSTGRES_PASSWORD=your-strong-password \
  -e POSTGRES_DB=vulnscanner \
  -p 5432:5432 \
  -v postgres_data:/var/lib/postgresql/data \
  -d postgres:15-alpine
```

### Using Docker Compose

Create a `docker-compose.postgres.yml`:

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    container_name: vulnscanner-postgres
    environment:
      POSTGRES_USER: vulnscanner
      POSTGRES_PASSWORD: your-strong-password
      POSTGRES_DB: vulnscanner
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U vulnscanner"]
      interval: 10s
      timeout: 5s
      retries: 5

volumes:
  postgres_data:
    driver: local
```

Run it:
```bash
docker-compose -f docker-compose.postgres.yml up -d
```

---

## Option 2: Install PostgreSQL Locally

### Windows
1. Download from: https://www.postgresql.org/download/windows/
2. Run installer
3. Note the username, password, and port (default: 5432)

### macOS
```bash
brew install postgresql@15
brew services start postgresql@15
```

### Linux (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install postgresql postgresql-contrib
sudo systemctl start postgresql
```

---

## Configure VulnScanner for PostgreSQL

### 1. Update `.env` file

```bash
# Backend
DATABASE_URL=postgresql://vulnscanner:your-strong-password@localhost:5432/vulnscanner
FLASK_ENV=production
JWT_SECRET=your-very-long-random-secret-key-here-min-32-chars
```

### 2. Update Frontend `.env.production`

```bash
VITE_API_URL=https://your-api.com
```

---

## Initialize Database

### Create Tables Automatically

The Flask app will create tables on first run:

```bash
cd backend
export DATABASE_URL="postgresql://user:password@host:5432/vulnscanner"
python -c "from app import app, db; app.app_context().push(); db.create_all(); print('✓ Database initialized')"
```

### Or using Flask Shell

```bash
cd backend
export DATABASE_URL="postgresql://user:password@host:5432/vulnscanner"
flask shell
>>> from app import db
>>> db.create_all()
>>> exit()
```

---

## Verify Connection

```bash
psql -U vulnscanner -h localhost -d vulnscanner
```

Or test with Python:

```python
from sqlalchemy import create_engine

engine = create_engine('postgresql://vulnscanner:password@localhost:5432/vulnscanner')
with engine.connect() as connection:
    result = connection.execute("SELECT 1")
    print("✓ PostgreSQL connection successful")
```

---

## Backup & Restore

### Backup Database

```bash
pg_dump -U vulnscanner -h localhost vulnscanner > backup.sql
```

### Restore Database

```bash
psql -U vulnscanner -h localhost vulnscanner < backup.sql
```

---

## Migration from SQLite to PostgreSQL

### Step 1: Export SQLite Data

```bash
python -c "
import sqlite3
import json
from datetime import datetime

conn = sqlite3.connect('vulnscanner.db')
cursor = conn.cursor()

# Export all tables
tables = cursor.execute(\"SELECT name FROM sqlite_master WHERE type='table'\").fetchall()
for table in tables:
    print(f'Exported {table[0]}')
"
```

### Step 2: Switch DATABASE_URL

```bash
export DATABASE_URL="postgresql://vulnscanner:password@localhost:5432/vulnscanner"
```

### Step 3: Recreate Tables

```bash
python -c "from app import app, db; app.app_context().push(); db.create_all()"
```

### Step 4: Restore Data (if needed)

Use data migration scripts or manual transfer depending on your requirements.

---

## Production Deployment

### Using Render.com

1. Create PostgreSQL database on Render.com
2. Get connection string:
   ```
   postgresql://user:password@hostname:5432/database
   ```
3. Set in production environment:
   ```
   DATABASE_URL=postgresql://user:password@hostname:5432/database
   ```

### Using Railway.app

1. Add PostgreSQL service
2. Railway automatically sets `DATABASE_URL` environment variable
3. Deploy - it will initialize automatically

### Using AWS RDS

1. Create RDS PostgreSQL instance
2. Get endpoint: `xxx.xxxxx.us-east-1.rds.amazonaws.com`
3. Set connection string:
   ```
   postgresql://user:password@xxx.rds.amazonaws.com:5432/vulnscanner
   ```

---

## Troubleshooting

### Connection Refused
- Check PostgreSQL is running: `sudo systemctl status postgresql`
- Verify port 5432 is open
- Check credentials in DATABASE_URL

### Permission Denied
- Verify user has database privileges:
  ```sql
  GRANT ALL PRIVILEGES ON DATABASE vulnscanner TO vulnscanner;
  ```

### Slow Queries
- Enable query logging:
  ```sql
  ALTER SYSTEM SET log_min_duration_statement = 1000;
  ```

---

## Performance Tips

1. **Add indexes** on frequently queried columns:
   ```sql
   CREATE INDEX idx_user_email ON users(email);
   CREATE INDEX idx_scan_user ON scans(user_id);
   CREATE INDEX idx_scan_status ON scans(status);
   ```

2. **Connection pooling** (already configured in Flask-SQLAlchemy)

3. **Regular maintenance:**
   ```sql
   VACUUM ANALYZE;
   ```

---

## Security Best Practices

- ✅ Use strong passwords (32+ characters)
- ✅ Restrict database access to backend only
- ✅ Enable SSL connections in production
- ✅ Regular backups (daily minimum)
- ✅ Monitor database logs
- ✅ Use environment variables for credentials (never hardcode)
