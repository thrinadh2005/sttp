# 🔐 Secure Penetration Testing Toolkit (SPTT)

An educational toolkit that simulates common offensive techniques and defensive controls so you can learn penetration testing fundamentals safely.

- CLI dashboard for guided exercises
- Flask-based web interface with real‑time logs
- Exportable reports (JSON/CSV)
- Built‑in security tips after each exercise

> IMPORTANT: For educational use only. Only test on systems you own or have explicit permission to assess. The authors assume no liability for misuse.

---

## 📦 What’s Inside

- Main CLI dashboard: [main.py](file:///d:/PROJECTS/SPTT/main.py)
- Web server: [web_app.py](file:///d:/PROJECTS/SPTT/web_app.py) and UI [index.html](file:///d:/PROJECTS/SPTT/templates/index.html)
- Modules:
  - Port scanning: [port_scanner.py](file:///d:/PROJECTS/SPTT/modules/port_scanner.py)
  - Hash cracking: [hash_cracker.py](file:///d:/PROJECTS/SPTT/modules/hash_cracker.py)
  - Brute‑force login simulation: [brute_force.py](file:///d:/PROJECTS/SPTT/modules/brute_force.py)
  - DNS tools (resolve/reverse): [dns_tools.py](file:///d:/PROJECTS/SPTT/modules/dns_tools.py)
  - HTTP header analyzer: [http_analyzer.py](file:///d:/PROJECTS/SPTT/modules/http_analyzer.py)
  - Password strength auditor: [password_auditor.py](file:///d:/PROJECTS/SPTT/modules/password_auditor.py)
- Utilities: [utils](file:///d:/PROJECTS/SPTT/utils)
- Quick launcher (Windows): [launch.bat](file:///d:/PROJECTS/SPTT/launch.bat)
- Python dependencies: [requirements.txt](file:///d:/PROJECTS/SPTT/requirements.txt)

---

## 🛠️ Installation

Prerequisites:
- Python 3.9+ recommended
- Windows, macOS, or Linux

Windows (PowerShell):

```powershell
cd d:\PROJECTS\SPTT
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

macOS/Linux:

```bash
cd /path/to/SPTT
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 🚀 Run The App

- CLI Dashboard:

```bash
python main.py
```
From the dashboard, choose “Launch Web Interface” to start the server from the menu.

- Web Interface (opens http://localhost:5000):

```bash
# Windows quick start
launch.bat

# Or cross‑platform
python web_app.py
```

---

## 🧭 How It Works

SPTT provides a guided, safe environment to:
- Scan ports (TCP/UDP) on allowed targets
- Explore password hashing weaknesses
- Simulate brute‑force attacks against a mock login system
- Perform DNS lookups and reverse lookups
- Inspect HTTP headers and common security headers
- Evaluate password strength with actionable suggestions

Both the CLI and Web UI execute the same underlying modules and summarize results with timestamps, attempts, and contextual tips.

---

## � Under the Hood

- Port scanning
  - TCP uses a connect attempt via sockets to detect open ports.
  - UDP sends a small datagram and treats response as open; silence is inconclusive.
  - Deep scans can run with multiple threads for faster coverage.
- Hash cracking
  - Uses Python’s hashlib for MD5/SHA1/SHA256.
  - Dictionary attack iterates a wordlist; brute force enumerates character combinations.
  - Tracks attempts, duration, and discovered passwords.
- Brute‑force login
  - MockLoginSystem stores SHA‑256 password hashes.
  - Enforces rate limiting and temporary lockout after failed attempts.
  - Records login history and outcomes for review.
- Web interface
  - Flask endpoints execute module functions.
  - Real‑time logs stream to the browser using Socket.IO.
  - Currently includes port scanning and security tips.

References: [main.py](file:///d:/PROJECTS/SPTT/main.py), [web_app.py](file:///d:/PROJECTS/SPTT/web_app.py)

---

## 📦 Result Schemas

- Port Scanner

```json
{
  "target": "127.0.0.1",
  "scan_type": "TCP",
  "open_ports": [
    {"port": 80, "service": "HTTP", "status": "OPEN", "protocol": "TCP"}
  ],
  "scan_start": "ISO-8601",
  "scan_end": "ISO-8601",
  "duration_seconds": 1.23
}
```

- Hash Cracker

```json
{
  "algorithm": "md5",
  "target_hash": "5f4dcc3b5aa765d61d8327deb882cf99",
  "found_password": "password",
  "attempts": 2,
  "start_time": "ISO-8601",
  "end_time": "ISO-8601",
  "duration_seconds": 0.02
}
```

- Brute Force Login

```json
{
  "target_username": "admin",
  "found_password": "admin123",
  "attack_successful": true,
  "attempts": 42,
  "start_time": "ISO-8601",
  "end_time": "ISO-8601",
  "duration_seconds": 3.5
}
```

---

## �� Modules and Examples

### 1) Port Scanner
- Techniques: TCP connect scans, UDP probes
- Modes: Common ports (fast), Port range (deep), Single port (custom)
- Output: Open/closed status, guessed service, timing summary

CLI walkthrough:
1. Start `python main.py`
2. Choose “Port Scanner”
3. Pick “Scan common ports (fast)”
4. Enter target `127.0.0.1` and protocol `TCP`
5. Review results and security tips

Programmatic example:

```python
from modules import PortScanner

scanner = PortScanner("127.0.0.1")
open_ports = scanner.scan_common_ports(protocol="TCP")
print(open_ports)
print(scanner.get_results())
```

Key reference: [port_scanner.py](file:///d:/PROJECTS/SPTT/modules/port_scanner.py)

---

### 2) Hash Cracker
- Algorithms: MD5, SHA‑1, SHA‑256, SHA‑512, SHA3‑256
- Attacks: Dictionary wordlist, configurable brute‑force, rule‑based mutations, mask patterns
- Extras: Built‑in common password list, hash generation utility

CLI walkthrough (dictionary):
1. Start `python main.py`
2. Choose “Hash Cracker” → “Dictionary attack”
3. Paste a hash, e.g. MD5 of “password”: `5f4dcc3b5aa765d61d8327deb882cf99`
4. Press Enter to use built‑in wordlist
5. See whether it’s found, attempts, and duration

Programmatic examples:

```python
from modules import HashCracker

# Dictionary attack
hc = HashCracker("5f4dcc3b5aa765d61d8327deb882cf99", "md5")
pwd, attempts = hc.crack_with_dictionary(["123456", "password", "letmein"])
print(pwd, attempts, hc.get_results())

# Brute force (short length!)
hc2 = HashCracker(hc.generate_hash("abc1"), "md5")
pwd2, attempts2 = hc2.crack_with_brute_force(max_length=4)
print(pwd2, attempts2, hc2.get_results())

# Rule-based mutations
hc3 = HashCracker(hc.generate_hash("Password123!"), "md5")
pwd3, attempts3 = hc3.crack_with_rules(["password"])
print(pwd3, attempts3, hc3.get_results())

# Mask attack (?l?l?l?d)
hc4 = HashCracker(hc.generate_hash("abc1"), "md5")
pwd4, attempts4 = hc4.crack_with_mask("?l?l?l?d")
print(pwd4, attempts4, hc4.get_results())
```

Key reference: [hash_cracker.py](file:///d:/PROJECTS/SPTT/modules/hash_cracker.py)

---

### 3) Brute Force Login
- Target: Mock login system with safe defenses
- Defenses: Account lockout, rate limiting, history tracking
- Uses: Demonstrate how defenses impact attacks

Default test users include `admin/admin123`, `user/password`, `test/test123`, `guest/guest`.

CLI walkthrough:
1. Start `python main.py`
2. Choose “Brute Force Login” → “Brute force attack”
3. Enter target username `admin`
4. Press Enter to use built‑in password list
5. Observe success, attempts, and defense behavior

Programmatic example:

```python
from modules import BruteForceLogin
from modules.brute_force import MockLoginSystem
from modules.hash_cracker import HashCracker

login_system = MockLoginSystem()
attacker = BruteForceLogin(login_system)
password_list = HashCracker.get_common_passwords()
pwd, attempts = attacker.brute_force_attack("admin", password_list)
print(pwd, attempts, attacker.get_results())
```

Key reference: [brute_force.py](file:///d:/PROJECTS/SPTT/modules/brute_force.py)

---

### 4) DNS Tools
- Actions: Resolve hostname to IPs, Reverse lookup IP to hostname
- Output: Addresses or hostname, timing summary

CLI walkthrough:
1. Start `python main.py`
2. Choose “Utilities” → “DNS Tools”
3. Select “resolve” and enter `example.com`
4. Review resolved addresses

Programmatic example:

```python
from modules import DNSTools

dns = DNSTools()
addrs = dns.resolve_host("example.com")
print(addrs, dns.get_results())
```

Key reference: [dns_tools.py](file:///d:/PROJECTS/SPTT/modules/dns_tools.py)

---

### 5) HTTP Header Analyzer
- Purpose: Inspect server headers and check presence of common security headers
- Output: Server, content type, security header presence matrix

CLI walkthrough:
1. Start `python main.py`
2. Choose “Utilities” → “HTTP Header Analyzer”
3. Enter `https://example.com`
4. Review reported headers and security indicators

Programmatic example:

```python
from modules import HTTPAnalyzer

ha = HTTPAnalyzer("https://example.com")
ha.fetch_headers()
ha.analyze()
print(ha.get_results())
```

Key reference: [http_analyzer.py](file:///d:/PROJECTS/SPTT/modules/http_analyzer.py)

---

### 6) Password Strength Auditor
- Purpose: Score password strength and list issues/suggestions
- Checks: Length, character classes, repeats, sequences, common passwords

CLI walkthrough:
1. Start `python main.py`
2. Choose “Utilities” → “Password Strength Audit”
3. Enter a password and review the score and suggestions

Programmatic example:

```python
from modules import PasswordAuditor

pa = PasswordAuditor()
result = pa.evaluate("P@ssw0rd123!")
print(result)
```

Key reference: [password_auditor.py](file:///d:/PROJECTS/SPTT/modules/password_auditor.py)

---

## 🌐 Web Interface

- Start with `launch.bat` (Windows) or `python web_app.py`
- Navigate to http://localhost:5000
- Real‑time activity log and results panel
- Run port scans, hash cracks, brute‑force simulations
- Utilities: DNS Tools, HTTP Header Analyzer, Password Strength Audit

Key server: [web_app.py](file:///d:/PROJECTS/SPTT/web_app.py) • UI: [index.html](file:///d:/PROJECTS/SPTT/templates/index.html)

---

### Web UI Walkthrough (New Utilities)

- DNS Tools
  1. Open the Web UI
  2. In the sidebar, under “Utilities”, select “DNS Tools”
  3. Choose “Resolve” and enter `example.com` or “Reverse” with an IP
  4. Review addresses or hostname in the Results panel

- HTTP Header Analyzer
  1. Select “HTTP Analyzer” under “Utilities”
  2. Enter a URL like `https://example.com`
  3. Review server, content-type, and security header presence

- Password Strength Audit
  1. Select “Password Audit” under “Utilities”
  2. Enter a password to evaluate
  3. See score, issues, and suggestions in Results

---
## 💾 Exporting Results

From the CLI dashboard:
1. Run any module
2. Choose “Export Results”
3. Select JSON or CSV
4. Files are saved as `results_YYYYMMDD_HHMMSS.json|csv` in the current directory

Implementation: see `export_results` in [main.py](file:///d:/PROJECTS/SPTT/main.py#L486-L516)

---

## 🛡️ Security Tips

After each exercise the app prints contextual tips:
- Close unnecessary ports and segment networks
- Enforce strong passwords and multi‑factor auth
- Use rate limiting and account lockout

Source: [security_tips.py](file:///d:/PROJECTS/SPTT/utils/security_tips.py)

---

## ❓ Troubleshooting

- Permission denied / connection refused: ensure you only scan allowed targets; localhost is safe for practice.
- Very slow brute force: reduce `max_length` or limit character set.
- Web server not starting: confirm Flask and Flask‑SocketIO are installed and the venv is activated.
- Windows PowerShell script execution policy: you may need `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` before activating the venv.

---

## 📜 License and Ethics

This project is for education and research. Use responsibly and lawfully.

