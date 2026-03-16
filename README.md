# 🛡️ VAPT Toolkit Pro (Python Edition)

A professional, menu-driven **VAPT (Vulnerability Assessment and Penetration Testing)** toolkit written in **Python**.  
This tool is designed for **security researchers, penetration testers, bug bounty hunters, and system administrators** to quickly perform automated security checks directly from the terminal.

The Python version improves upon the Bash toolkit by adding **colorized output, threaded scanning, modular architecture, and improved cross-platform compatibility.**

---

## 🚀 Key Features

- **Unified CLI Interface**  
  One command to launch a menu-driven security toolkit with a clean ASCII banner.

- **Modular Architecture**  
  Each scanner runs as an independent module inside `vapt_modules/`.

- **Colorized Terminal Output**  
  Professional CLI output similar to Kali Linux tools.

- **Threaded Scanning**  
  Fast multi-threaded port scanning for improved performance.

- **Cross Platform Support**  
  Works on **Linux, macOS, and Windows**.

- **Security-Focused Design**  
  Includes basic input validation to prevent misuse and reduce SSRF risks.

- **Automated Vulnerability Summary**  
  Displays a consolidated list of detected issues after scans.

---

# 🛠️ Included Modules

| Module | Description |
|------|-------------|
| **Headers Check** | Detects missing HTTP security headers (CSP, HSTS, XFO, Referrer-Policy, etc.) |
| **SSL/TLS Audit** | Validates certificate details and TLS configuration |
| **DNS Misconfiguration** | Checks origin exposure for potential CDN/WAF bypass |
| **Port Scanner** | Multi-threaded scanner for common open ports |
| **CORS Check** | Detects CORS misconfigurations such as wildcard or reflected origins |
| **Output Engine** | Provides colorized terminal output similar to Kali tools |
| **Banner Module** | Displays ASCII banner and CLI interface |
| **Vulnerability Summary** | Generates a summary of detected issues |

--More are Coming Soon--
---

# 📂 Project Structure
VAPT-Toolkit-Pro-Python
│
├── vapt.py
├── vapt_modules
│ ├── banner.py
│ ├── cors_check.py
│ ├── dns_check.py
│ ├── headers.py
│ ├── output.py
│ ├── port_scan.py
│ ├── ssl_check.py
│ └── vapt_summary.py
│
├── LICENSE
└── README.md


---

# 📥 Installation

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/VAPT-Toolkit-Pro-Python.git
cd VAPT-Toolkit-Pro-Python
2️⃣ Install Dependencies
pip install requests colorama
▶️ Usage

Run the toolkit:

python3 vapt.py

Python 3.8+

requests

colorama

Supported Platforms:

Linux

macOS

Windows

⚡ Future Improvements

Planned features for upcoming versions:

Automated full scan mode

Technology fingerprinting


📄 License

This project is licensed under the MIT License.
See the LICENSE file for details.

⚠️ Disclaimer

This tool is intended for educational purposes and authorized security testing only.

Running security scans against systems without permission is illegal and may violate local laws.