# 🚀 Deployment Guide

Your ScamScan application is now ready for deployment! You have multiple options:

## Option 1: Docker (Recommended for Self-Hosting)

### Quick Start
```bash
# Build and run with Docker Compose
docker-compose up -d --build

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

**Access:** `http://localhost:8000`

### Deploy to Cloud with Docker
Works on any cloud provider supporting Docker:
- **DigitalOcean App Platform**: Connect GitHub repo, auto-detects Dockerfile
- **AWS ECS/Fargate**: Push image to ECR, deploy to Fargate
- **Google Cloud Run**: `gcloud run deploy --source .`
- **Azure Container Apps**: Deploy directly from container registry

---

## Option 2: Vercel (Serverless)

⚠️ **Note**: Vercel has limitations for long-running OSINT sweeps (10s timeout on free tier). Best for URL scanning only.

### Setup Steps:
1. **Install Vercel CLI**:
   ```bash
   npm install -g vercel
   ```

2. **Create API Entry Point** (already handled in `web/app.py`):
   The app is structured as a FastAPI server which Vercel can adapt.

3. **Deploy**:
   ```bash
   vercel login
   vercel --prod
   ```

4. **Environment Variables** (Set in Vercel Dashboard):
   - `PORT`: 8000
   - Any API keys you use

### ⚠️ Vercel Limitations:
- **Sweep Feature**: May timeout on free tier (10s limit). Upgrade to Pro for 60s.
- **Database**: SQLite won't persist between requests. Switch to PostgreSQL (Neon/Supabase) for production.
- **Background Tasks**: OSINT discovery works better on platforms allowing longer execution.

---

## Option 3: Traditional VPS (Ubuntu/Debian)

### 1. Install Dependencies
```bash
sudo apt update
sudo apt install python3-pip python3-venv nginx git -y
```

### 2. Setup Application
```bash
cd /var/www/scamscan
git clone <your-repo> .
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Create Systemd Service
Create `/etc/systemd/system/scamscan.service`:
```ini
[Unit]
Description=ScamScan Web App
After=network.target

[Service]
User=www-data
WorkingDirectory=/var/www/scamscan
ExecStart=/var/www/scamscan/venv/bin/uvicorn web.app:app --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
```

### 4. Enable & Start
```bash
sudo systemctl enable scamscan
sudo systemctl start scamscan
sudo systemctl status scamscan
```

### 5. Configure Nginx (Reverse Proxy)
Create `/etc/nginx/sites-available/scamscan`:
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Increase timeouts for OSINT sweeps
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

Enable site:
```bash
sudo ln -s /etc/nginx/sites-available/scamscan /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

## Option 4: Railway / Render (Easiest PaaS)

### Railway
1. Connect GitHub repository
2. Auto-detects Python/Docker
3. Add environment variables in dashboard
4. Deploy automatically on push

### Render
1. New Web Service → Connect Repo
2. Build Command: `pip install -r requirements.txt`
3. Start Command: `uvicorn web.app:app --host 0.0.0.0 --port $PORT`
4. Set `PORT` environment variable

---

## 🔧 Production Recommendations

### 1. Database Migration
Switch from SQLite to PostgreSQL for production:
```bash
# Add to requirements.txt
psycopg2-binary
sqlalchemy[asyncio]

# Use connection string in .env
DATABASE_URL=postgresql://user:pass@host:5432/dbname
```

### 2. Environment Variables
Create `.env` file (add to `.gitignore`):
```env
PORT=8000
DATABASE_URL=sqlite+aiosqlite:///./data/scamscan.db
GOOGLE_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
SECRET_KEY=your-secret-key-for-sessions
```

### 3. Security
- Enable HTTPS (Let's Encrypt)
- Add rate limiting
- Sanitize all user inputs
- Use CORS properly configured

### 4. Monitoring
- Add health check endpoint (`/health`)
- Log errors to stdout/stderr
- Consider Sentry for error tracking

---

## 🏃 Quick Test Before Deploy

```bash
# Test locally with Docker
docker-compose up --build

# Or test directly
python -m uvicorn web.app:app --reload
```

Visit `http://localhost:8000` to verify everything works before deploying!
