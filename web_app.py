"""
SPTT Web Interface
Flask web server with real-time log streaming
"""

import os
import sys
import io
import json
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit

from modules import PortScanner, HashCracker, BruteForceLogin
from modules.brute_force import MockLoginSystem
from modules import DNSTools, HTTPAnalyzer, PasswordAuditor
from utils import SecurityTips

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sptt-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Global state for logs and results
logs = []
results = {}


def log_message(message, level="info"):
    """Log a message and emit to web clients."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    log_entry = {
        'timestamp': timestamp,
        'message': message,
        'level': level
    }
    logs.append(log_entry)
    # Keep only last 500 logs
    if len(logs) > 500:
        logs.pop(0)
    # Emit to web clients
    try:
        socketio.emit('log_update', log_entry)
    except Exception:
        pass


class OutputCapture:
    """Capture stdout/stderr and send to web interface."""
    
    def __init__(self, socketio):
        self.socketio = socketio
        self.buffer = io.StringIO()
        
    def write(self, text):
        if text.strip():
            self.buffer.write(text)
            log_message(text.rstrip(), "output")
            
    def flush(self):
        pass
    
    def get_value(self):
        return self.buffer.getvalue()


@app.route('/')
def index():
    """Render the main page."""
    return render_template('index.html')


@app.route('/api/logs')
def get_logs():
    """Get all logs."""
    return jsonify({'logs': logs})


@app.route('/api/results')
def get_results():
    """Get all results."""
    return jsonify({'results': results})


@app.route('/api/clear', methods=['POST'])
def clear_logs():
    """Clear logs and results."""
    global logs, results
    logs = []
    results = {}
    log_message("Logs and results cleared", "info")
    return jsonify({'status': 'success'})


@app.route('/api/port_scan', methods=['POST'])
def port_scan():
    """Execute port scan."""
    data = request.json
    target = data.get('target', '')
    scan_type = data.get('scan_type', 'common')
    protocol = data.get('protocol', 'TCP')
    
    log_message(f"Starting port scan on {target}", "info")
    log_message(f"Scan type: {scan_type}, Protocol: {protocol}", "info")
    
    try:
        scanner = PortScanner(target)
        
        if scan_type == 'common':
            open_ports = scanner.scan_common_ports(protocol)
        else:
            start_port = int(data.get('start_port', 1))
            end_port = int(data.get('end_port', 100))
            open_ports = scanner.scan_port_range(start_port, end_port, protocol)
        
        scan_results = scanner.get_results()
        results['port_scanner'] = scan_results
        
        log_message(f"Scan completed. Found {len(open_ports)} open ports.", "success")
        
        # Show security tips
        tips = SecurityTips.get_port_scanner_tips()
        log_message("🛡️ Security Tips:", "tip")
        for tip in tips[:3]:
            log_message(f"  {tip}", "tip")
        
        return jsonify({'status': 'success', 'results': scan_results})
        
    except Exception as e:
        log_message(f"Error: {str(e)}", "error")
        return jsonify({'status': 'error', 'message': str(e)})




@app.route('/api/hash_cracker', methods=['POST'])
def hash_cracker():
    """Execute hash cracking attacks."""
    data = request.json
    hash_value = data.get('hash_value', '').strip()
    algorithm = data.get('algorithm', 'md5').lower()
    attack_type = data.get('attack_type', 'dictionary')
    
    if not hash_value:
        return jsonify({'status': 'error', 'message': 'Hash value is required'})
    
    try:
        cracker = HashCracker(hash_value, algorithm)
        log_message(f"Starting hash crack | algo={algorithm} | type={attack_type}", "info")
        
        if attack_type == 'dictionary':
            wordlist = data.get('wordlist') or HashCracker.get_common_passwords()
            pwd, attempts = cracker.crack_with_dictionary(wordlist, show_progress=False)
        elif attack_type == 'brute':
            max_length = int(data.get('max_length', 4))
            pwd, attempts = cracker.crack_with_brute_force(max_length=max_length, show_progress=False)
        elif attack_type == 'rules':
            wordlist = data.get('wordlist') or HashCracker.get_common_passwords()
            prefixes = data.get('prefixes') or None
            suffixes = data.get('suffixes') or None
            if isinstance(prefixes, str):
                prefixes = [p.strip() for p in prefixes.split(',') if p.strip()]
            if isinstance(suffixes, str):
                suffixes = [s.strip() for s in suffixes.split(',') if s.strip()]
            pwd, attempts = cracker.crack_with_rules(wordlist, suffixes=suffixes, prefixes=prefixes, show_progress=False)
        elif attack_type == 'mask':
            mask = data.get('mask', '?l?l?l?d')
            pwd, attempts = cracker.crack_with_mask(mask, show_progress=False)
        else:
            return jsonify({'status': 'error', 'message': 'Unsupported attack_type'})
        
        hc_results = cracker.get_results()
        results['hash_cracker'] = hc_results
        
        if hc_results.get('found_password'):
            log_message(f"Success: password found after {hc_results.get('attempts')} attempts", "success")
        else:
            log_message("Completed: password not found", "warning")
        
        # Security tips
        tips = SecurityTips.get_hash_cracker_tips()
        log_message("🛡️ Security Tips:", "tip")
        for tip in tips[:3]:
            log_message(f"  {tip}", "tip")
        
        return jsonify({'status': 'success', 'results': hc_results})
    
    except Exception as e:
        log_message(f"Error: {str(e)}", "error")
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/brute_force', methods=['POST'])
def brute_force():
    """Execute brute force login simulation."""
    data = request.json
    username = data.get('username', '').strip()
    action = data.get('attack_type', 'attack')
    
    if not username and action == 'attack':
        return jsonify({'status': 'error', 'message': 'Username is required'})
    
    try:
        login_system = MockLoginSystem()
        attacker = BruteForceLogin(login_system)
        
        if action == 'demo':
            log_message("Demonstrating defenses (lockout and rate limiting)", "info")
            attacker.demonstrate_defenses()
            bf_results = {'demo': True}
        else:
            log_message(f"Starting brute force against user '{username}'", "info")
            password_list = data.get('password_list') or HashCracker.get_common_passwords()
            pwd, attempts = attacker.brute_force_attack(username, password_list, show_progress=False)
            bf_results = attacker.get_results()
        
        results['brute_force'] = bf_results
        
        tips = SecurityTips.get_brute_force_tips()
        log_message("🛡️ Security Tips:", "tip")
        for tip in tips[:3]:
            log_message(f"  {tip}", "tip")
        
        return jsonify({'status': 'success', 'results': bf_results})
    
    except Exception as e:
        log_message(f"Error: {str(e)}", "error")
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/security_tips', methods=['GET'])
def get_security_tips():
    """Get security tips."""
    category = request.args.get('category', 'all')
    
    if category == 'port_scanner':
        tips = SecurityTips.get_port_scanner_tips()
    elif category == 'hash_cracker':
        tips = SecurityTips.get_hash_cracker_tips()
    elif category == 'brute_force':
        tips = SecurityTips.get_brute_force_tips()
    else:
        tips = SecurityTips.get_general_tips()
    
    return jsonify({'tips': tips})

@app.route('/api/ping')
def ping():
    """Health check endpoint."""
    return jsonify({'status': 'ok'})

@app.route('/api/dns_tools', methods=['POST'])
def dns_tools():
    """DNS resolve/reverse utilities."""
    data = request.json or {}
    action = data.get('action', 'resolve')
    query = data.get('query', '').strip()
    if not query:
        return jsonify({'status': 'error', 'message': 'Query is required'})
    try:
        tool = DNSTools()
        if action == 'reverse':
            log_message(f"DNS reverse lookup for {query}", "info")
            hostname = tool.reverse_lookup(query)
            log_message(f"Reverse result: {hostname or 'Unknown'}", "info")
        else:
            log_message(f"DNS resolve for {query}", "info")
            addrs = tool.resolve_host(query)
            log_message(f"Resolve result: {', '.join(addrs) if addrs else 'None'}", "info")
        res = tool.get_results()
        results['dns_tools'] = res
        return jsonify({'status': 'success', 'results': res})
    except Exception as e:
        log_message(f"Error: {str(e)}", "error")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/http_analyzer', methods=['POST'])
def http_analyzer():
    """HTTP header analyzer."""
    data = request.json or {}
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'status': 'error', 'message': 'URL is required'})
    try:
        log_message(f"Fetching headers for {url}", "info")
        analyzer = HTTPAnalyzer(url)
        analyzer.fetch_headers()
        analyzer.analyze()
        res = analyzer.get_results()
        results['http_analyzer'] = res
        sec = res.get('analysis', {}).get('security_headers', {})
        log_message("Security headers summary:", "tip")
        for k, v in sec.items():
            log_message(f"  {k}: {v}", "tip")
        return jsonify({'status': 'success', 'results': res})
    except Exception as e:
        log_message(f"Error: {str(e)}", "error")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/password_audit', methods=['POST'])
def password_audit():
    """Password strength auditing."""
    data = request.json or {}
    password = data.get('password', '')
    if not password:
        return jsonify({'status': 'error', 'message': 'Password is required'})
    try:
        auditor = PasswordAuditor()
        res = auditor.evaluate(password)
        results['password_auditor'] = res
        log_message(f"Password score: {res.get('score')}", "info")
        if res.get('issues'):
            log_message("Issues detected:", "warning")
            for i in res['issues'][:5]:
                log_message(f"  {i}", "warning")
        return jsonify({'status': 'success', 'results': res})
    except Exception as e:
        log_message(f"Error: {str(e)}", "error")
        return jsonify({'status': 'error', 'message': str(e)})

if __name__ == '__main__':
    log_message("="*50, "info")
    log_message("🔐 SPTT Web Interface Starting...", "info")
    log_message("Open http://localhost:5000 in your browser", "info")
    log_message("="*50, "info")
    
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
