# NIKHIL AI - VAPT Toolkit Deployment Guide

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Local Testing](#local-testing)
3. [Deployment Options](#deployment-options)
4. [Production Deployment](#production-deployment)
5. [Domain & SSL Setup](#domain--ssl-setup)
6. [Security Hardening](#security-hardening)
7. [Monitoring & Maintenance](#monitoring--maintenance)

---

## Prerequisites

### System Requirements
- **OS**: Linux (Ubuntu 20.04 LTS recommended), Windows Server, or macOS
- **Python**: 3.8 or higher
- **RAM**: Minimum 2GB, recommended 4GB+
- **Storage**: Minimum 10GB free space
- **Network**: Stable internet connection, static IP (recommended)

### Required Software
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3 python3-pip python3-venv git curl nginx

# CentOS/RHEL
sudo yum install python3 python3-pip git curl nginx

# macOS
brew install python3 nginx
```

### Python Dependencies
```bash
pip install flask flask-cors requests colorama gunicorn
```

---

## Local Testing

### 1. Clone Repository
```bash
git clone https://github.com/Hema-Satya-Nikhil/VAPT-Toolkit-Pro-Python.git
cd VAPT-Toolkit-Pro-Python
```

### 2. Create Virtual Environment
```bash
# Linux/macOS
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run Flask Development Server
```bash
python app.py
```
Access at: `http://localhost:5000`

### 5. Run Tests
```bash
# Test all endpoints
curl http://localhost:5000/
curl -X POST http://localhost:5000/api/validate -H "Content-Type: application/json" -d '{"url":"https://google.com"}'
curl -X POST http://localhost:5000/api/scan/headers -H "Content-Type: application/json" -d '{"url":"https://google.com"}'
```

---

## Deployment Options

### Option 1: Heroku (Easy, Free Tier Limited)
**Pros**: One-click deployment, automatic HTTPS  
**Cons**: Limited free tier, slower performance

#### Steps:
```bash
# 1. Install Heroku CLI
# Download from: https://devcenter.heroku.com/articles/heroku-cli

# 2. Login to Heroku
heroku login

# 3. Create Procfile (already created in repo)
# Procfile content:
# web: gunicorn app:app

# 4. Create requirements.txt (already created)

# 5. Deploy
git push heroku main

# 6. Open app
heroku open
```

### Option 2: DigitalOcean (Recommended - $6-$12/month)
**Pros**: Fast, reliable, great documentation, affordable  
**Cons**: More manual setup required

### Option 3: AWS (Scalable, Complex Setup)
**Pros**: Highly scalable, many services available  
**Cons**: Complex configuration, can become expensive

### Option 4: Self-Hosted Linux VPS
**Pros**: Full control, cost-effective for long-term  
**Cons**: Requires server management knowledge

---

## Production Deployment (Recommended: DigitalOcean)

### 1. Acquire VPS Instance
- Sign up at [DigitalOcean.com](https://www.digitalocean.com)
- Create a Droplet with:
  - OS: Ubuntu 20.04 LTS
  - Plan: $6/month (2GB RAM, 1 vCPU, 50GB SSD)
  - Region: Closest to your target audience
  - Add SSH keys for security

### 2. Initial Server Setup
```bash
# SSH into server
ssh root@YOUR_SERVER_IP

# Update system
apt-get update && apt-get upgrade -y

# Create non-root user
adduser nikhil
usermod -aG sudo nikhil

# Switch to new user
su - nikhil
```

### 3. Install Dependencies
```bash
sudo apt-get install -y python3 python3-pip python3-venv git nginx

# Optional: Install SSL certificate generation tool
sudo apt-get install -y certbot python3-certbot-nginx
```

### 4. Clone Repository
```bash
cd /home/nikhil
git clone https://github.com/Hema-Satya-Nikhil/VAPT-Toolkit-Pro-Python.git
cd VAPT-Toolkit-Pro-Python
```

### 5. Create Python Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 6. Setup Gunicorn (Production WSGI Server)
```bash
pip install gunicorn

# Test Gunicorn
gunicorn -w 4 -b 127.0.0.1:8000 app:app
```

### 7. Create Systemd Service File
```bash
sudo nano /etc/systemd/system/nikhil-vapt.service
```

Add the following:
```ini
[Unit]
Description=NIKHIL VAPT Toolkit
After=network.target

[Service]
User=nikhil
WorkingDirectory=/home/nikhil/VAPT-Toolkit-Pro-Python
Environment="PATH=/home/nikhil/VAPT-Toolkit-Pro-Python/venv/bin"
ExecStart=/home/nikhil/VAPT-Toolkit-Pro-Python/venv/bin/gunicorn -w 4 -b 127.0.0.1:8000 app:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable nikhil-vapt
sudo systemctl start nikhil-vapt
sudo systemctl status nikhil-vapt
```

### 8. Configure Nginx as Reverse Proxy
```bash
sudo nano /etc/nginx/sites-available/nikhil-vapt
```

Add the following:
```nginx
server {
    listen 80;
    server_name your-domain.com www.your-domain.com;

    client_max_body_size 20M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_redirect off;
        
        # Timeout settings for long scans
        proxy_connect_timeout 60s;
        proxy_send_timeout 120s;
        proxy_read_timeout 120s;
    }

    # Gzip compression
    gzip on;
    gzip_types text/plain text/css text/javascript application/json;
    gzip_min_length 1000;
}
```

Enable the site:
```bash
sudo ln -s /etc/nginx/sites-available/nikhil-vapt /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default

# Test Nginx configuration
sudo nginx -t

# Restart Nginx
sudo systemctl restart nginx
```

---

## Domain & SSL Setup

### 1. Register Domain
- Register at [Namecheap.com](https://www.namecheap.com), [GoDaddy.com](https://www.godaddy.com), or [Google Domains](https://domains.google)
- Total cost: $10-15/year

### 2. Point Domain to Server
- Go to domain provider's DNS settings
- Create A record: `@` → `YOUR_SERVER_IP`
- Create A record: `www` → `YOUR_SERVER_IP`
- Wait 24-48 hours for DNS propagation

### 3. Setup Free SSL Certificate (Let's Encrypt)
```bash
sudo certbot certonly --nginx -d your-domain.com -d www.your-domain.com

# You'll be prompted for email and agreement
# Certificate will be generated automatically
```

### 4. Update Nginx Configuration for HTTPS
```bash
sudo nano /etc/nginx/sites-available/nikhil-vapt
```

Replace with:
```nginx
server {
    listen 80;
    server_name your-domain.com www.your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com www.your-domain.com;

    # SSL certificates
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    client_max_body_size 20M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_redirect off;
        
        proxy_connect_timeout 60s;
        proxy_send_timeout 120s;
        proxy_read_timeout 120s;
    }

    gzip on;
    gzip_types text/plain text/css text/javascript application/json;
    gzip_min_length 1000;
}
```

Restart Nginx:
```bash
sudo systemctl restart nginx
```

### 5. Auto-Renew SSL Certificate
```bash
# Test auto-renewal
sudo certbot renew --dry-run

# Enable auto-renewal
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer
```

---

## Security Hardening

### 1. Firewall Configuration
```bash
# Enable UFW (Uncomplicated Firewall)
sudo ufw enable
sudo ufw allow 22/tcp      # SSH
sudo ufw allow 80/tcp      # HTTP
sudo ufw allow 443/tcp     # HTTPS
sudo ufw status
```

### 2. Fail2Ban (Prevent Brute Force Attacks)
```bash
sudo apt-get install fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

### 3. Update Security Headers in app.py
```python
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response
```

### 4. Rate Limiting
```bash
pip install flask-limiter
```

Update app.py:
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(app=app, key_func=get_remote_address)

@app.route('/api/scan/all', methods=['POST'])
@limiter.limit("5 per minute")
def scan_all():
    # ... existing code
```

### 5. Environment Variables
```bash
# Create .env file
nano /home/nikhil/VAPT-Toolkit-Pro-Python/.env
```

Add:
```
FLASK_ENV=production
FLASK_DEBUG=False
SECRET_KEY=your-secret-key-here-change-this
```

Update app.py:
```python
from dotenv import load_dotenv
import os

load_dotenv()

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-change-in-production')
app.config['DEBUG'] = os.getenv('FLASK_DEBUG', False)
```

---

## Monitoring & Maintenance

### 1. Setup Logging
```bash
# Create logs directory
mkdir -p /home/nikhil/VAPT-Toolkit-Pro-Python/logs

# Configure logrotate
sudo nano /etc/logrotate.d/nikhil-vapt
```

Add:
```
/home/nikhil/VAPT-Toolkit-Pro-Python/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    notifempty
    create 0640 nikhil nikhil
    sharedscripts
}
```

### 2. Monitor Server Health
```bash
# CPU and Memory usage
top

# Disk usage
df -h

# Check service status
sudo systemctl status nikhil-vapt
```

### 3. Update Application
```bash
cd /home/nikhil/VAPT-Toolkit-Pro-Python
git pull origin main
source venv/bin/activate
pip install -r requirements.txt
sudo systemctl restart nikhil-vapt
```

### 4. Backup Strategy
```bash
# Create backup script
nano ~/backup-nikhil-vapt.sh
```

Add:
```bash
#!/bin/bash
BACKUP_DIR="/home/nikhil/backups"
mkdir -p $BACKUP_DIR
tar -czf $BACKUP_DIR/nikhil-vapt-$(date +%Y%m%d-%H%M%S).tar.gz \
  /home/nikhil/VAPT-Toolkit-Pro-Python

# Keep only last 7 backups
find $BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete
```

Schedule with cron:
```bash
# Add to crontab
crontab -e

# Add line:
0 2 * * * /home/nikhil/backup-nikhil-vapt.sh
```

---

## Troubleshooting

### Issue: Port 8000 already in use
```bash
# Find process using port
sudo lsof -i :8000

# Kill process
sudo kill -9 <PID>
```

### Issue: Nginx not connecting to Gunicorn
```bash
# Check if Gunicorn is running
sudo systemctl status nikhil-vapt

# Check Nginx error logs
sudo tail -f /var/log/nginx/error.log

# Restart both services
sudo systemctl restart nikhil-vapt
sudo systemctl restart nginx
```

### Issue: SSL Certificate not renewing
```bash
sudo certbot renew --force-renewal
sudo systemctl restart nginx
```

### Issue: High Memory Usage
```bash
# Adjust Gunicorn workers
# Edit /etc/systemd/system/nikhil-vapt.service
# Change: gunicorn -w 4 -b 127.0.0.1:8000 app:app
# To: gunicorn -w 2 -b 127.0.0.1:8000 app:app
# Then restart
```

---

## Performance Optimization

### 1. Enable Caching
```python
from flask_caching import Cache

cache = Cache(app, config={'CACHE_TYPE': 'simple'})

@app.route('/api/validate', methods=['POST'])
@cache.cached(timeout=300)
def validate():
    # ... existing code
```

### 2. Database Setup (Optional)
```bash
pip install flask-sqlalchemy
```

### 3. CDN Integration
- Upload static files to CloudFlare CDN
- Update static file URLs in templates

### 4. Database Optimization (for future)
```bash
# Install PostgreSQL
sudo apt-get install postgresql postgresql-contrib

# Will be used for storing scan history and user data
```

---

## Cost Breakdown (Monthly Estimate)

| Service | Cost | Notes |
|---------|------|-------|
| DigitalOcean Droplet | $6-12 | Depending on size |
| Domain | $1 | If you own it yearly |
| SSL Certificate | FREE | Let's Encrypt |
| Bandwidth | Included | 1TB included |
| **Total** | **~$7/month** | Very affordable! |

---

## Final Checklist

- [ ] Domain registered and DNS configured
- [ ] SSL certificate installed and auto-renewal enabled
- [ ] Firewall configured and running
- [ ] Application running as systemd service
- [ ] Nginx configured as reverse proxy
- [ ] HTTPS redirect working
- [ ] Security headers implemented
- [ ] Backup strategy in place
- [ ] Monitoring logs configured
- [ ] Performance optimizations applied
- [ ] Documentation updated
- [ ] Team trained on deployment process

---

## Support & Documentation

- **GitHub Issues**: [Report bugs](https://github.com/Hema-Satya-Nikhil/VAPT-Toolkit-Pro-Python/issues)
- **Documentation**: See README.md for detailed information
- **Flask Docs**: https://flask.palletsprojects.com
- **DigitalOcean Docs**: https://docs.digitalocean.com
- **Let's Encrypt**: https://letsencrypt.org

---

**Last Updated**: 2026-05-10  
**Version**: 1.0  
**Author**: NIKHIL AI Team
