"""
Flask backend API for NIKHIL AI VAPT Toolkit
Provides REST endpoints for all scanning modules
"""
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import json
import threading
from urllib.parse import urlparse
import ipaddress
import socket

from nikhil_ai_modules.headers import check_headers
from nikhil_ai_modules.ssl_check import check_ssl
from nikhil_ai_modules.dns_check import check_dns
from nikhil_ai_modules.cors_check import check_cors
from nikhil_ai_modules.port_scan import scan_ports

app = Flask(__name__)
CORS(app)

# Store scan results
scan_results = {}


def validate_target(url):
    """Validate target URL for SSRF protection"""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    
    if parsed.scheme not in ["http", "https"]:
        raise ValueError("Only HTTP/HTTPS URLs allowed")
    
    host = parsed.hostname
    
    if host in ["localhost", "127.0.0.1"]:
        raise ValueError("Localhost targets are blocked")
    
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback:
            raise ValueError("Private IP ranges are not allowed")
    except ValueError as e:
        if "Private IP ranges are not allowed" in str(e):
            raise
        pass
    
    return url


@app.route('/')
def index():
    """Serve the main dashboard"""
    return render_template('index.html')


@app.route('/api/validate', methods=['POST'])
def validate():
    """Validate target URL"""
    try:
        data = request.json
        url = data.get('url', '')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        validated_url = validate_target(url)
        return jsonify({'success': True, 'url': validated_url}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/scan/headers', methods=['POST'])
def scan_headers():
    """Scan for missing security headers"""
    try:
        data = request.json
        url = validate_target(data.get('url', ''))
        
        result = check_headers(url)
        return jsonify({'success': True, 'data': result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/scan/ssl', methods=['POST'])
def scan_ssl():
    """Scan SSL/TLS configuration"""
    try:
        data = request.json
        url = validate_target(data.get('url', ''))
        
        result = check_ssl(url)
        return jsonify({'success': True, 'data': result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/scan/dns', methods=['POST'])
def scan_dns():
    """Check DNS misconfiguration"""
    try:
        data = request.json
        url = validate_target(data.get('url', ''))
        parsed = urlparse(url)
        domain = parsed.hostname
        
        result = check_dns(domain)
        return jsonify({'success': True, 'data': result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/scan/cors', methods=['POST'])
def scan_cors():
    """Check CORS misconfiguration"""
    try:
        data = request.json
        url = validate_target(data.get('url', ''))
        
        result = check_cors(url)
        return jsonify({'success': True, 'data': result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/scan/ports', methods=['POST'])
def scan_ports_endpoint():
    """Scan for open ports"""
    try:
        data = request.json
        url = validate_target(data.get('url', ''))
        parsed = urlparse(url)
        target = parsed.hostname
        
        result = scan_ports(target)
        return jsonify({'success': True, 'data': result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/scan/all', methods=['POST'])
def scan_all():
    """Run all scans"""
    try:
        data = request.json
        url = validate_target(data.get('url', ''))
        parsed = urlparse(url)
        domain = parsed.hostname
        
        results = {
            'headers': check_headers(url),
            'ssl': check_ssl(url),
            'dns': check_dns(domain),
            'cors': check_cors(url),
            'ports': scan_ports(domain)
        }
        
        return jsonify({'success': True, 'data': results}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
