# 🛡️ NIKHIL AI - Web Frontend UI

A professional, cybersecurity-themed web interface for the NIKHIL AI VAPT (Vulnerability Assessment & Penetration Testing) Toolkit.

## 🎨 Features

### **Unique Hacker Theme Design**
- ✨ Dark cybersecurity aesthetic with green/cyan neon colors
- 🔤 Glitch text animation on main heading
- 🌊 Matrix background pattern for immersive experience
- ✨ Smooth animations and transitions throughout
- 📱 Fully responsive design (desktop, tablet, mobile)

### **UI Components**
- **Sidebar Navigation**: Quick access to all 6 scan modules
- **Input Validation**: Real-time URL validation with SSRF protection
- **Progress Tracking**: Live progress bars for each scanning module
- **Results Dashboard**: Tabbed interface for detailed results
- **Info Panels**: Context-sensitive help and security notices
- **Toast Notifications**: Real-time feedback and status updates
- **Export Functionality**: Download scan results as JSON

### **Scan Modules**
1. **Full Scan** - Comprehensive security assessment
2. **Security Headers** - HTTP header analysis
3. **SSL/TLS Audit** - Certificate and protocol audit
4. **DNS Check** - DNS misconfiguration detection
5. **CORS Check** - CORS policy validation
6. **Port Scan** - Open port enumeration

## 🚀 Quick Start

### Prerequisites
```bash
pip install Flask Flask-CORS requests colorama
```

### Installation

1. **Navigate to project directory**:
```bash
cd D:\VAPT-Toolkit-Pro-Python
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

3. **Start the Flask server**:
```bash
python app.py
```

4. **Open in browser**:
```
http://localhost:5000
```

## 📁 Project Structure

```
NIKHIL-AI/
├── app.py                          # Flask backend API
├── requirements.txt                # Python dependencies
├── templates/
│   └── index.html                 # Main HTML interface
├── static/
│   ├── css/
│   │   └── style.css              # Hacker theme styling
│   └── js/
│       └── script.js              # Frontend interactivity
└── nikhil_ai_modules/             # Security scanning modules
    ├── headers.py
    ├── ssl_check.py
    ├── dns_check.py
    ├── cors_check.py
    ├── port_scan.py
    └── banner.py
```

## 🎮 Usage

### **Web Interface**
1. Select a scan module from the sidebar
2. Enter target URL (e.g., `https://example.com` or `example.com`)
3. Click **INITIATE SCAN** or press `Ctrl+Enter`
4. View real-time progress and results
5. Switch between tabs to explore different findings
6. Export results by clicking **Export**

### **Keyboard Shortcuts**
- `Ctrl+Enter` - Start scan
- `Esc` - Reset scanner

### **API Endpoints**

#### Validate Target
```bash
POST /api/validate
Content-Type: application/json

{
  "url": "https://example.com"
}
```

#### Run Scan
```bash
POST /api/scan/all              # Full scan
POST /api/scan/headers          # Security headers
POST /api/scan/ssl              # SSL/TLS audit
POST /api/scan/dns              # DNS check
POST /api/scan/cors             # CORS check
POST /api/scan/ports            # Port scan
```

## 🎨 Design Highlights

### **Color Scheme**
- **Primary**: `#00ff00` (Neon Green)
- **Secondary**: `#00ffff` (Cyan)
- **Danger**: `#ff006e` (Hot Pink)
- **Background**: `#0a0a0a` (Deep Black)

### **Animations**
- Glitch text effect
- Pulse animations for status indicators
- Shimmer effect on progress bars
- Smooth transitions on all interactive elements
- Fade-in/out for tab switching

### **Typography**
- Monospace font: `Courier New`
- Uppercase text for headers
- Letter spacing for cyberpunk aesthetic

## 🔒 Security Features

### **SSRF Protection**
- Blocks localhost and private IP ranges
- Validates URL format before scanning
- Prevents access to internal network resources

### **Input Validation**
- Real-time URL validation
- Automatic HTTPS protocol addition
- Error feedback with detailed messages

### **Safe Execution**
- Thread-safe port scanning
- Configurable timeouts
- Graceful error handling

## 🛠️ API Response Format

### Success Response
```json
{
  "success": true,
  "data": {
    "headers": { /* header data */ },
    "ssl": { /* SSL data */ },
    "dns": { /* DNS data */ },
    "cors": { /* CORS data */ },
    "ports": { /* port data */ }
  }
}
```

### Error Response
```json
{
  "error": "Error message describing the issue"
}
```

## 📊 Results Display

### **Summary Tab**
Overview of all scanned modules with status indicators

### **Headers Tab**
- Missing security headers (red)
- Present headers (green)
- Vulnerability details

### **SSL/TLS Tab**
- Certificate information
- Protocol support status
- Expiry warnings

### **DNS Tab**
- Resolved IP address
- Public/Private designation
- Origin exposure indicators

### **CORS Tab**
- CORS headers analysis
- Vulnerability detection
- Policy strength assessment

### **Ports Tab**
- Open ports table
- Service identification
- Vulnerability indicators

## 🎯 Advanced Features

### **Real-Time Progress**
- Visual progress bars for each module
- Elapsed time counter
- Status indicator with pulsing animation

### **Export Functionality**
- Download results as JSON
- Timestamped filenames
- Full scan history preservation

### **Responsive Design**
- Desktop: Full 3-column layout
- Tablet: Sidebar hidden, expanded content
- Mobile: Single column layout

## 🚨 Notes

1. **Testing Restrictions**: Only test targets you own or have explicit permission to test
2. **External Tools**: Nmap integration requires system installation
3. **SSL Warnings**: Some self-signed certificate sites may show warnings
4. **Timeout Configuration**: Default timeout is 5 seconds per request
5. **Rate Limiting**: No built-in rate limiting - use responsibly

## 🔧 Configuration

### **Development Server**
```python
# In app.py
app.run(debug=True, host='0.0.0.0', port=5000)
```

### **Production Deployment**
```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

## 📝 License

This project is open-source and part of the NIKHIL AI VAPT Toolkit.

## 👨‍💻 Developer

**NIKHIL**
- GitHub: [@Hema-Satya-Nikhil](https://github.com/Hema-Satya-Nikhil)
- Repository: [NIKHIL_ai_tool](https://github.com/Hema-Satya-Nikhil/Nikhil_ai_tool)

## ⚠️ Legal Disclaimer

This tool is intended for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before testing any systems. Unauthorized access to computer systems is illegal.

---

**Status**: ✅ Production Ready | **Version**: 1.0.0 | **Last Updated**: May 2026
