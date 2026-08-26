# Deploy to Railway

Your FraudGuard AI application is now ready for Railway deployment!

## 🚀 Quick Deploy Steps

### Option 1: One-Click Deploy (Easiest)
1. Click this button: [Deploy on Railway](https://railway.app/template/new)
2. Connect your GitHub repository
3. Railway will auto-detect the `railway.json` and deploy automatically

### Option 2: Manual Deploy via CLI
```bash
# Install Railway CLI
npm install -g @railway/cli

# Login to Railway
railway login

# Initialize project (if not already done)
railway init

# Deploy
railway up
```

## ⚙️ Configuration

The `railway.json` file is already configured with:
- **Builder**: Nixpacks (automatic Python environment detection)
- **Start Command**: Runs the FastAPI server on the correct port
- **Health Check**: Monitors the root endpoint `/`
- **Auto-restart**: Restarts on failure with max 10 retries

## 🔧 Environment Variables (Optional)

Set these in Railway Dashboard → Settings → Variables if needed:
- `DUCKDUCKGO_LIMIT`: Max search results (default: 10)
- `SCAN_TIMEOUT`: Timeout for scans in seconds (default: 30)
- `REVIEW_THRESHOLD`: Minimum score to flag as scam (default: 45)

## 🌐 After Deployment

1. Railway will provide you with a public URL (e.g., `https://your-app.railway.app`)
2. Share this URL to access the UI from anywhere
3. The OSINT sweep and URL scanner will work globally

## 📊 Monitoring

- View logs in Railway Dashboard
- Monitor resource usage (CPU, Memory, Network)
- Set up alerts for failures or high resource usage

## 💡 Tips

- **Free Tier**: Railway offers $5/month free credit (enough for light usage)
- **Scaling**: Upgrade plan if you need more concurrent searches
- **Database**: SQLite works fine for small-medium usage; consider PostgreSQL for production scale
- **Rate Limits**: Be mindful of DuckDuckGo/API rate limits with heavy usage

## 🔒 Security Notes

- Add a simple auth layer if exposing publicly (optional)
- Monitor for abuse of the scanning endpoints
- Keep dependencies updated regularly

---

**Ready to deploy?** Just push your code to GitHub and connect it to Railway!
