# VulnScanner Production Deployment Guide

This guide covers deploying VulnScanner to production with PostgreSQL.

## Quick Start

### 1. Prerequisites

- Docker & Docker Compose installed
- Git repository cloned
- Domain name (for SSL/HTTPS)
- Strong passwords generated

### 2. Environment Setup

Copy the production template:

```bash
cp .env.production.example .env.production
```

Edit `.env.production`:

```bash
# Security (MUST CHANGE)
JWT_SECRET=<generate-32-char-random-string>

# Database
DB_USER=vulnscanner
DB_PASSWORD=<strong-random-password-32-chars>
DB_NAME=vulnscanner
DB_PORT=5432

# Flask
FLASK_ENV=production
FLASK_DEBUG=false

# Frontend
VITE_API_URL=https://your-domain.com

# Backend Port
BACKEND_PORT=5000
FRONTEND_PORT=3000

# Optional
SHODAN_API_KEY=your-key-here
LOG_LEVEL=INFO
```

### 3. Generate Secure Values

```bash
# Generate JWT secret
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# Generate database password
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

### 4. Deploy with Docker Compose

```bash
# Build images
docker-compose -f docker-compose.production.yml build

# Start services
docker-compose -f docker-compose.production.yml up -d

# View logs
docker-compose -f docker-compose.production.yml logs -f backend
```

### 5. Initialize Database

```bash
# Create tables
docker-compose -f docker-compose.production.yml exec backend python -c \
  "from app import app, db; app.app_context().push(); db.create_all()"

# Create admin user (if needed)
docker-compose -f docker-compose.production.yml exec backend python create_admin.py
```

---

## Platform-Specific Deployment

### Railway.app (Easiest)

1. **Connect GitHub:**
   - Go to railway.app
   - Click "New Project" → "Deploy from GitHub repo"
   - Select your VulnScanner repo

2. **Add PostgreSQL Service:**
   - Click "Add" → PostgreSQL
   - Railway auto-creates `DATABASE_URL` environment variable

3. **Add Backend Service:**
   - Settings → Build Command: (leave empty)
   - Start Command: `python app.py`

4. **Add Frontend Service:**
   - Settings → Build Command: `npm run build`
   - Start Command: `npm run preview`
   - Environment: `VITE_API_URL=https://your-railway-backend.railway.app`

5. **Set Environment Variables:**
   ```
   JWT_SECRET=your-generated-secret
   FLASK_ENV=production
   ```

6. **Deploy!**

---

### Render.com

1. **Create PostgreSQL Database:**
   - Go to render.com
   - New → PostgreSQL
   - Get internal connection string

2. **Deploy Backend:**
   - New → Web Service
   - Connect GitHub repo (backend directory)
   - Environment Variables:
     ```
     DATABASE_URL=<internal-db-connection>
     JWT_SECRET=your-secret
     FLASK_ENV=production
     ```
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn app:app`

3. **Deploy Frontend:**
   - New → Static Site
   - Connect GitHub repo (frontend directory)
   - Build Command: `npm run build`
   - Publish Directory: `dist`
   - Environment: `VITE_API_URL=<backend-url>`

---

### Heroku

```bash
# Login
heroku login

# Create app
heroku create your-app-name

# Add PostgreSQL
heroku addons:create heroku-postgresql:hobby-dev

# Set environment variables
heroku config:set JWT_SECRET=your-secret
heroku config:set FLASK_ENV=production

# Deploy
git push heroku main
```

---

### AWS (Elastic Beanstalk)

```bash
# Install EB CLI
pip install awsebcli

# Initialize
eb init -p "Python 3.11 running on 64bit Amazon Linux 2" vulnscanner

# Create environment
eb create production

# Deploy
eb deploy
```

---

### DigitalOcean App Platform

1. **Create App:**
   - Apps → Create App
   - Connect GitHub repo
   - Choose backend directory

2. **Add PostgreSQL Database:**
   - Resources → Create → Database
   - Select PostgreSQL

3. **Configure Backend Service:**
   - Source: GitHub repo
   - Build: `pip install -r requirements.txt`
   - Run: `gunicorn app:app`

4. **Add Environment Variables:**
   ```
   DATABASE_URL (auto-created by DigitalOcean)
   JWT_SECRET=your-secret
   FLASK_ENV=production
   ```

---

## SSL/HTTPS Setup

### Using Let's Encrypt with Nginx

```bash
# Install certbot
sudo apt-get install certbot python3-certbot-nginx

# Get certificate
sudo certbot certonly --nginx -d your-domain.com

# Update nginx.conf with certificate paths
# (See nginx.conf example below)

# Auto-renew
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer
```

---

## Monitoring & Maintenance

### Check Services

```bash
# View all containers
docker ps

# View logs
docker logs -f <container-name>

# Check database connection
docker exec <backend-container> python -c \
  "from app import db; print(db.engine.url)"
```

### Backup Database

```bash
# Manual backup
docker exec <postgres-container> pg_dump -U vulnscanner vulnscanner > backup.sql

# Restore
docker exec -i <postgres-container> psql -U vulnscanner vulnscanner < backup.sql
```

### Performance Monitoring

```bash
# Check Docker resource usage
docker stats

# Monitor database connections
docker exec <postgres-container> psql -U vulnscanner -c \
  "SELECT datname, count(*) FROM pg_stat_activity GROUP BY datname;"
```

---

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker-compose -f docker-compose.production.yml logs backend

# Rebuild
docker-compose -f docker-compose.production.yml build --no-cache
```

### Database Connection Error

```bash
# Verify DATABASE_URL
docker-compose exec backend python -c "import os; print(os.getenv('DATABASE_URL'))"

# Test connection
docker exec postgres psql -U vulnscanner -c "SELECT 1;"
```

### Frontend Can't Reach Backend

```bash
# Check VITE_API_URL
docker-compose exec frontend env | grep VITE

# Verify backend is running
curl https://your-domain.com/health
```

---

## Security Checklist

- ✅ Strong passwords (32+ characters)
- ✅ JWT_SECRET is unique and random
- ✅ DATABASE_URL uses strong password
- ✅ HTTPS/SSL enabled
- ✅ Environment variables not in code
- ✅ `.env` files not committed to git
- ✅ Firewall rules restrict database access
- ✅ Regular backups enabled
- ✅ Logs monitored for errors
- ✅ Update dependencies regularly

---

## Scaling Tips

- Use **connection pooling** (Flask-SQLAlchemy handles this)
- Add **Redis caching** for frequently accessed data
- Use **CDN** for static assets (Cloudflare, AWS CloudFront)
- Configure **auto-scaling** on cloud platforms
- Add **load balancer** for multiple backend instances

---

## Next Steps

1. Choose your deployment platform
2. Follow platform-specific guide above
3. Test production environment
4. Set up monitoring/alerts
5. Create backup procedures
