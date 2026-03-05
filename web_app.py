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
from utils import SecurityTips

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sptt-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")

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
    socketio.emit('log_update', log_entry)


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
    """Execute hash crack."""
    data = request.json
    hash_value = data.get('hash_value', '')
    algorithm = data.get('algorithm', 'md5')
    attack_type = data.get('attack_type', 'dictionary')
    
    log_message(f"Starting hash cracker", "info")
    log_message(f"Hash: {hash_value[:20]}...", "info")
    log_message(f"Algorithm: {algorithm}, Attack: {attack_type}", "info")
    
    try:
        cracker = HashCracker(hash_value, algorithm)
        
        if attack_type == 'dictionary':
            wordlist = HashCracker.get_common_passwords()
            password, attempts = cracker.crack_with_dictionary(wordlist, show_progress=False)
        else:
            max_length = int(data.get('max_length', 4))
            password, attempts = cracker.crack_with_brute_force(max_length, show_progress=False)
        
        crack_results = cracker.get_results()
        results['hash_cracker'] = crack_results
        
        if password:
            log_message(f"✅ Password found: {password}", "success")
        else:
            log_message("❌ Password not found", "warning")
        
        # Show security tips
        tips = SecurityTips.get_hash_cracker_tips()
        log_message("🛡️ Security Tips:", "tip")
        for tip in tips[:3]:
            log_message(f"  {tip}", "tip")
        
        return jsonify({'status': 'success', 'results': crack_results})
        
    except Exception as e:
        log_message(f"Error: {str(e)}", "error")
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/api/brute_force', methods=['POST'])
def brute_force():
    """Execute brute force login attack."""
    data = request.json
    target_user = data.get('username', '')
    attack_type = data.get('attack_type', 'attack')
    
    log_message(f"Brute Force Login - {attack_type}", "info")
    
    try:
        login_system = MockLoginSystem()
        brute_force = BruteForceLogin(login_system)
        
        if attack_type == 'attack':
            password_list = HashCracker.get_common_passwords()
            password, attempts = brute_force.brute_force_attack(
                target_user, password_list, show_progress=False
            )
        else:
            # Demo defenses
            brute_force.demonstrate_defenses()
            password = "demo"
            attempts = 0
        
        bf_results = brute_force.get_results()
        results['brute_force'] = bf_results
        
        if password and attack_type == 'attack':
            log_message(f"✅ Password found: {password}", "success")
        
        # Show security tips
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


if __name__ == '__main__':
    log_message("="*50, "info")
    log_message("🔐 SPTT Web Interface Starting...", "info")
    log_message("Open http://localhost:5000 in your browser", "info")
    log_message("="*50, "info")
    
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
