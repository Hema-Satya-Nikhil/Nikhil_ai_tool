"""
Flask backend API for NIKHIL AI VAPT Toolkit
Provides REST endpoints for all scanning modules
"""
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import json
import threading
import io
import sys
import time
from contextlib import redirect_stdout, redirect_stderr
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

def capture_function_output(func, *args):
    """Capture stdout from scanning functions"""
    try:
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = buffer_out = io.StringIO()
        sys.stderr = buffer_err = io.StringIO()
        
        result = func(*args)
        
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        
        output = buffer_out.getvalue()
        errors = buffer_err.getvalue()
        
        return {
            'success': True,
            'result': result,
            'output': output,
            'errors': errors
        }
    except Exception as e:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        return {
            'success': False,
            'error': str(e),
            'output': buffer_out.getvalue() if 'buffer_out' in locals() else '',
            'errors': buffer_err.getvalue() if 'buffer_err' in locals() else ''
        }


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
        
        scan_result = capture_function_output(check_headers, url)
        
        if scan_result['success']:
            return jsonify({
                'success': True,
                'data': scan_result['result'],
                'output': scan_result['output']
            }), 200
        else:
            return jsonify({'error': scan_result['error'], 'output': scan_result['output']}), 400
    except Exception as e:
        return jsonify({'error': f"Headers scan failed: {str(e)}"}), 500


@app.route('/api/scan/ssl', methods=['POST'])
def scan_ssl():
    """Scan SSL/TLS configuration"""
    try:
        data = request.json
        url = validate_target(data.get('url', ''))
        
        scan_result = capture_function_output(check_ssl, url)
        
        if scan_result['success']:
            return jsonify({
                'success': True,
                'data': scan_result['result'],
                'output': scan_result['output']
            }), 200
        else:
            return jsonify({'error': scan_result['error'], 'output': scan_result['output']}), 400
    except Exception as e:
        return jsonify({'error': f"SSL scan failed: {str(e)}"}), 500


@app.route('/api/scan/dns', methods=['POST'])
def scan_dns():
    """Check DNS misconfiguration"""
    try:
        data = request.json
        url = validate_target(data.get('url', ''))
        parsed = urlparse(url)
        domain = parsed.hostname
        
        scan_result = capture_function_output(check_dns, domain)
        
        if scan_result['success']:
            return jsonify({
                'success': True,
                'data': scan_result['result'],
                'output': scan_result['output']
            }), 200
        else:
            return jsonify({'error': scan_result['error'], 'output': scan_result['output']}), 400
    except Exception as e:
        return jsonify({'error': f"DNS scan failed: {str(e)}"}), 500


@app.route('/api/scan/cors', methods=['POST'])
def scan_cors():
    """Check CORS misconfiguration"""
    try:
        data = request.json
        url = validate_target(data.get('url', ''))
        
        scan_result = capture_function_output(check_cors, url)
        
        if scan_result['success']:
            return jsonify({
                'success': True,
                'data': scan_result['result'],
                'output': scan_result['output']
            }), 200
        else:
            return jsonify({'error': scan_result['error'], 'output': scan_result['output']}), 400
    except Exception as e:
        return jsonify({'error': f"CORS scan failed: {str(e)}"}), 500


@app.route('/api/scan/ports', methods=['POST'])
def scan_ports_endpoint():
    """Scan for open ports"""
    try:
        data = request.json
        url = validate_target(data.get('url', ''))
        parsed = urlparse(url)
        target = parsed.hostname
        
        scan_result = capture_function_output(scan_ports, target)
        
        if scan_result['success']:
            return jsonify({
                'success': True,
                'data': scan_result['result'],
                'output': scan_result['output']
            }), 200
        else:
            return jsonify({'error': scan_result['error'], 'output': scan_result['output']}), 400
    except Exception as e:
        return jsonify({'error': f"Port scan failed: {str(e)}"}), 500


@app.route('/api/scan/all', methods=['POST'])
def scan_all():
    """Run all scans"""
    try:
        data = request.json
        url = validate_target(data.get('url', ''))
        parsed = urlparse(url)
        domain = parsed.hostname
        
        results = {}
        
        # Run each scan with error handling
        headers_result = capture_function_output(check_headers, url)
        results['headers'] = headers_result['result'] if headers_result['success'] else {'error': headers_result['error']}
        
        ssl_result = capture_function_output(check_ssl, url)
        results['ssl'] = ssl_result['result'] if ssl_result['success'] else {'error': ssl_result['error']}
        
        dns_result = capture_function_output(check_dns, domain)
        results['dns'] = dns_result['result'] if dns_result['success'] else {'error': dns_result['error']}
        
        cors_result = capture_function_output(check_cors, url)
        results['cors'] = cors_result['result'] if cors_result['success'] else {'error': cors_result['error']}
        
        ports_result = capture_function_output(scan_ports, domain)
        results['ports'] = ports_result['result'] if ports_result['success'] else {'error': ports_result['error']}
        
        return jsonify({'success': True, 'data': results}), 200
    except Exception as e:
        return jsonify({'error': f"Full scan failed: {str(e)}"}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
