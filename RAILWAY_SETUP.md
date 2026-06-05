# Railway.app Deployment - Step by Step Guide

Railway is the easiest way to deploy VulnScanner with PostgreSQL. Free tier includes $5/month credit.

## Prerequisites

- GitHub account (your VulnScanner repo)
- Railway account (free at railway.app)
- Generated secrets (see section below)

---

## Step 1: Generate Secure Secrets

Generate a strong JWT secret before deploying:

### Option A: Using PowerShell (Windows)
```powershell
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### Option B: Using Terminal (Mac/Linux)
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Copy the output - you'll use this for `JWT_SECRET`.

**Example output:**
```
aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5
```

---

## Step 2: Create Railway Project

1. **Go to** https://railway.app
2. **Sign up** with GitHub (or existing account)
3. Click **"New Project"** button
4. Select **"Deploy from GitHub repo"**
5. **Authorize Railway** to access your GitHub repos
6. **Select** `VulnScanner` repository
7. Click **"Deploy"**

---

## Step 3: Add PostgreSQL Database

1. **In Railway dashboard**, click **"+ Add Service"**
2. Select **"PostgreSQL"**
3. PostgreSQL container starts automatically
4. Railway creates `DATABASE_URL` environment variable automatically ✓

---

## Step 4: Configure Environment Variables

1. **In Railway dashboard**, select your project
2. Go to **"Variables"** tab
3. Add the following:

| Name | Value | Note |
|------|-------|------|
| `FLASK_ENV` | `production` | Required |
| `FLASK_DEBUG` | `false` | Required |
| `JWT_SECRET` | `<paste-generated-secret>` | Use from Step 1 |
| `LOG_LEVEL` | `INFO` | Optional |
| `SHODAN_API_KEY` | `<your-key>` | Optional |

4. Click **"Save"**

**Important:** Railway auto-creates `DATABASE_URL` - don't add it manually!

---

## Step 5: Configure Backend Service

1. **In Railway dashboard**, select backend service
2. Click **"Settings"** (gear icon)
3. Find **"Root Directory"** → Set to `/backend`
4. Find **"Start Command"** → Set to:
   ```
   gunicorn app:app
   ```
   (or `python app.py` if gunicorn fails)

5. Find **"Port"** → Should be `5000`
6. Click **"Save"**

### Install gunicorn dependency

Update `backend/requirements.txt`:

```bash
# Add at end of file
gunicorn==21.2.0
```

Then commit and push:
```bash
git add backend/requirements.txt
git commit -m "Add gunicorn for production"
git push
```

---

## Step 6: Configure Frontend Service

1. **In Railway dashboard**, select frontend service
2. Click **"Settings"** (gear icon)
3. Find **"Root Directory"** → Set to `/frontend`
4. Find **"Build Command"** → Set to:
   ```
   npm run build
   ```
5. Find **"Start Command"** → Set to:
   ```
   npm run preview
   ```
6. Add environment variable:
   - Name: `VITE_API_URL`
   - Value: `https://<your-backend-url>.railway.app`
   
   (You'll get the URL after backend deploys)
7. Click **"Save"**

---

## Step 7: Wait for Builds & Deployments

1. **Railway auto-detects** your project structure
2. **Builds start** → Watch progress in Deployments tab
3. **Wait for both services** to show green checkmarks ✓

**Build times:**
- Backend: 2-3 minutes
- Frontend: 2-3 minutes

---

## Step 8: Get Your URLs

1. **Backend URL** (from Railway dashboard):
   ```
   https://vulnscanner-prod-backend.railway.app
   ```

2. **Frontend URL**:
   ```
   https://vulnscanner-prod-frontend.railway.app
   ```

---

## Step 9: Initialize Database

1. **Go to Backend service → "Logs"**
2. Check for any errors
3. Run database initialization:
   
   **Option A: Using Railway CLI**
   ```bash
   # Install Railway CLI
   npm i -g @railway/cli
   
   # Login
   railway login
   
   # Run command in remote environment
   railway run python -c "from app import app, db; app.app_context().push(); db.create_all()"
   ```

   **Option B: Using HTTP request**
   ```bash
   curl -X POST https://<your-backend-url>/api/init-db \
     -H "Content-Type: application/json"
   ```

---

## Step 10: Create Admin User (Optional)

Run remotely on Railway:

```bash
railway run python create_admin.py
```

Or manually via admin panel once deployed.

---

## Step 11: Update Frontend API URL

Update your frontend environment variables with the actual backend URL:

1. **In Railway**, select frontend service
2. **Variables** → Update `VITE_API_URL`
   ```
   https://vulnscanner-prod-backend.railway.app
   ```
3. **Redeploy** → Click "Redeploy" on latest deployment

---

## Step 12: Test Your Deployment

1. **Visit frontend URL:**
   ```
   https://vulnscanner-prod-frontend.railway.app
   ```

2. **Test login** (if created admin user)

3. **Check backend health:**
   ```
   https://vulnscanner-prod-backend.railway.app/health
   ```
   Should return `200 OK`

---

## Troubleshooting

### Build Failed
- Check **Deployment Logs** → "Build Logs"
- Common issues:
  - Missing `requirements.txt` in backend
  - Missing `package.json` in frontend
  - Wrong Python version

### Backend Won't Connect to Database
- Check `DATABASE_URL` exists in variables
- Verify PostgreSQL service is running
- Check logs: `psycopg2` errors → database connection issue

### Frontend Can't Reach Backend
- Verify `VITE_API_URL` is set correctly
- Check backend is deployed and running
- Test: `curl https://<backend-url>/health`

### Service Won't Start
1. Check **Deployment Logs**
2. Verify **Start Command** is correct
3. Check for missing dependencies:
   ```bash
   railway run pip list  # Check installed packages
   ```

---

## Maintenance & Updates

### Deploy Updates

```bash
# Make changes locally
git commit -m "Your changes"
git push

# Railway auto-deploys on push to main branch!
```

### View Logs

```bash
# Using Railway CLI
railway logs -f  # Follow logs in real-time

# Or in Dashboard → Service → Logs
```

### Restart Service

```bash
# Using Railway CLI
railway restart

# Or in Dashboard → Deployments → Click service → Restart
```

### Update Environment Variables

1. Go to Railway Dashboard
2. Select service → Variables
3. Edit and save
4. Service auto-redeploys

---

## Database Management

### Backup Database

```bash
# Export data
railway run pg_dump -U $(echo $DATABASE_URL | cut -d: -f2) > backup.sql

# Or use Railway backups (automatic daily)
```

### Connect to Database Locally

```bash
# Get connection string
railway vars | grep DATABASE_URL

# Connect with psql
psql <connection-string>
```

---

## Scaling & Performance

### Add More Resources

Railway automatically scales, but you can:

1. **Upgrade service tier** → More CPU/RAM
2. **Add Redis cache** → New service + `REDIS_URL` variable
3. **Enable autoscaling** → Service settings

### Monitor Usage

1. Dashboard → **"Usage"** tab
2. View CPU, RAM, bandwidth usage
3. Compare against $5/month free credit

---

## Cost Estimate

| Resource | Cost |
|----------|------|
| Backend (small) | ~$1-2/month |
| Frontend (small) | ~$0.50-1/month |
| PostgreSQL (small) | ~$1-2/month |
| **Total** | **~$3-5/month** ✓ **Within free tier!** |

---

## Custom Domain (Optional)

1. **Buy domain** (GoDaddy, Namecheap, etc.)
2. **In Railway**, go to service
3. **Settings** → **"Domains"**
4. **Add domain** → Add your domain
5. Update DNS records with Railway's nameservers
6. SSL certificate auto-generated ✅

---

## Security Best Practices

✅ **Environment variables** - All secrets in variables, not code
✅ **SSL/HTTPS** - Auto-generated Railway certificates
✅ **Database** - PostgreSQL encrypted, isolated network
✅ **Backups** - Railway auto-backups daily
✅ **JWT Secret** - Strong, random, unique per deployment
✅ **No hardcoded credentials** - Use env vars only

---

## Success Checklist

- ✅ Repository connected to Railway
- ✅ PostgreSQL database created
- ✅ Environment variables set
- ✅ Backend service deploying successfully
- ✅ Frontend service deploying successfully
- ✅ Database initialized with tables
- ✅ Frontend can reach backend API
- ✅ Login works
- ✅ Scans can run
- ✅ Reports generate

---

## Next Steps

1. **Test everything** in production
2. **Create backup procedure** (optional - Railway handles this)
3. **Monitor logs** for errors
4. **Set up alerts** (optional Railway Pro feature)
5. **Share your app!** 🎉

---

## Support

**Railway Support:** https://railway.app/support
**VulnScanner Issues:** Check GitHub repo issues

---

## What You Get for $5/month (Free Credit)

✅ PostgreSQL database with automatic backups
✅ Docker container deployments
✅ Automatic SSL/HTTPS
✅ Custom domain support
✅ Environment variable management
✅ Deployment history & rollback
✅ Real-time logs
✅ Git integration (auto-deploy on push)
✅ 1GB bandwidth/month
✅ Email support

**That's everything you need!** 🚀
