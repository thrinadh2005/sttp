"""
SPTT - Secure Penetration Testing Toolkit
Main Dashboard - Entry point for the toolkit
"""

import os
import sys
import json
import csv
from datetime import datetime
from typing import Optional, Dict, List

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules import PortScanner, HashCracker, BruteForceLogin
from modules.brute_force import MockLoginSystem
from utils import setup_logger, SecurityTips


class SPTTDashboard:
    """
    Main dashboard for the Secure Penetration Testing Toolkit.
    Provides CLI interface for all modules.
    """
    
    def __init__(self):
        """Initialize the dashboard."""
        self.logger = setup_logger('SPTT')
        self.current_results: Dict = {}
        
    def clear_screen(self):
        """Clear the terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_header(self):
        """Print the application header."""
        print("\n" + "="*60)
        print("🔐 Secure Penetration Testing Toolkit (SPTT)")
        print("="*60)
        print("📚 Educational Purpose Only - Use Responsibly")
        print("="*60 + "\n")
    
    def print_menu(self):
        """Print the main menu."""
        print("\n📋 MAIN MENU")
        print("-" * 40)
        print("1. 🔍 Port Scanner")
        print("2. 🔓 Hash Cracker")
        print("3. 🔐 Brute Force Login")
        print("4. 🛡️ Security Tips")
        print("5. 📊 View Previous Results")
        print("6. 💾 Export Results")
        print("7. ℹ️  About")
        print("8. 🌐 Launch Web Interface")
        print("9. 🧰 Utilities")
        print("0. 🚪 Exit")
        print("-" * 40)
    
    def get_user_choice(self, options: List[str] = None) -> str:
        """Get and validate user choice."""
        while True:
            choice = input("\n👉 Enter your choice: ").strip()
            if options:
                if choice in options:
                    return choice
                print("❌ Invalid choice. Please try again.")
            else:
                return choice
    
    def validate_ip(self, ip: str) -> bool:
        """Validate IP address or hostname."""
        import re
        # Basic hostname/IP validation
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        if re.match(pattern, ip) or self._is_valid_ip(ip):
            return True
        return False
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IP address."""
        import re
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, ip):
            parts = ip.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        return False
    
    def validate_port(self, port: str) -> bool:
        """Validate port number."""
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except ValueError:
            return False
    
    def validate_hash(self, hash_value: str) -> tuple:
        """Validate hash value and determine algorithm."""
        hash_value = hash_value.strip().lower()
        
        if len(hash_value) == 32:
            return (True, 'md5')
        elif len(hash_value) == 40:
            return (True, 'sha1')
        elif len(hash_value) == 64:
            return (True, 'sha256')
        else:
            return (False, None)
    
    # ==================== PORT SCANNER MODULE ====================
    
    def port_scanner_menu(self):
        """Port Scanner module menu."""
        print("\n" + "="*60)
        print("🔍 PORT SCANNER MODULE")
        print("="*60)
        print("1. Scan common ports (fast)")
        print("2. Scan port range (deep scan)")
        print("3. Custom scan")
        print("0. Back to main menu")
        print("-" * 40)
        
        choice = input("\n👉 Enter choice: ").strip()
        
        if choice == '0':
            return
        
        # Get target
        target = input("\n🎯 Enter target IP or hostname: ").strip()
        if not target:
            print("❌ Target is required!")
            return
        
        if not self.validate_ip(target):
            print("❌ Invalid IP address or hostname!")
            return
        
        # Create scanner
        scanner = PortScanner(target)
        
        if choice == '1':
            # Common ports scan
            protocol = input("Protocol (TCP/UDP) [default: TCP]: ").strip().upper() or "TCP"
            results = scanner.scan_common_ports(protocol)
            self.current_results['port_scanner'] = scanner.get_results()
            
        elif choice == '2':
            # Port range scan
            start_port = input("Start port [default: 1]: ").strip() or "1"
            end_port = input("End port [default: 100]: ").strip() or "100"
            
            if not self.validate_port(start_port) or not self.validate_port(end_port):
                print("❌ Invalid port number!")
                return
            
            protocol = input("Protocol (TCP/UDP) [default: TCP]: ").strip().upper() or "TCP"
            threads = input("Number of threads [default: 1]: ").strip() or "1"
            
            try:
                threads = int(threads)
            except ValueError:
                threads = 1
            
            results = scanner.scan_port_range(
                int(start_port), int(end_port), protocol, threads
            )
            self.current_results['port_scanner'] = scanner.get_results()
            
        elif choice == '3':
            # Custom scan
            port = input("Enter port to scan: ").strip()
            if not self.validate_port(port):
                print("❌ Invalid port number!")
                return
            
            protocol = input("Protocol (TCP/UDP) [default: TCP]: ").strip().upper() or "TCP"
            
            if protocol == "TCP":
                port_num, is_open, service = scanner.scan_tcp_port(int(port))
            else:
                port_num, is_open, service = scanner.scan_udp_port(int(port))
            
            print(f"\n{'='*60}")
            print(f"🔍 Scan Result for {target}:{port}")
            print(f"{'='*60}")
            print(f"Port:    {port_num}")
            print(f"Status:  {'OPEN' if is_open else 'CLOSED'}")
            print(f"Service: {service}")
            print(f"{'='*60}\n")
            
        # Show security tips
        print("\n")
        SecurityTips.display_tips(SecurityTips.get_port_scanner_tips(), 
                                   "🛡️ Port Scanner Security Tips")
    
    # ==================== HASH CRACKER MODULE ====================
    
    def hash_cracker_menu(self):
        """Hash Cracker module menu."""
        print("\n" + "="*60)
        print("🔓 HASH CRACKER MODULE")
        print("="*60)
        print("1. Dictionary attack")
        print("2. Brute force attack")
        print("3. Generate hash")
        print("4. Use common passwords wordlist")
        print("5. Rule-based mutations")
        print("6. Mask attack")
        print("0. Back to main menu")
        print("-" * 40)
        
        choice = input("\n👉 Enter choice: ").strip()
        
        if choice == '0':
            return
        
        if choice in ['1', '2', '3', '5', '6']:
            # Get hash value
            hash_value = input("\n🔑 Enter hash value: ").strip()
            valid, algorithm = self.validate_hash(hash_value)
            
            if not valid:
                print("❌ Invalid hash value!")
                print("   Supported: MD5 (32 chars), SHA1 (40 chars), SHA256 (64 chars)")
                return
            
            # Override algorithm if user specifies
            algo_input = input(f"Algorithm [{algorithm}]: ").strip().lower()
            if algo_input in ['md5', 'sha1', 'sha256', 'sha512', 'sha3_256']:
                algorithm = algo_input
            
            cracker = HashCracker(hash_value, algorithm)
            
            if choice == '1':
                # Dictionary attack
                wordlist_file = input("Wordlist file (press Enter for built-in): ").strip()
                
                if wordlist_file and os.path.exists(wordlist_file):
                    with open(wordlist_file, 'r') as f:
                        wordlist = [line.strip() for line in f if line.strip()]
                else:
                    print("   Using built-in common passwords list...")
                    wordlist = HashCracker.get_common_passwords()
                
                show_progress = input("Show progress? (Y/n) [default: Y]: ").strip().lower() != 'n'
                password, attempts = cracker.crack_with_dictionary(wordlist, show_progress)
                self.current_results['hash_cracker'] = cracker.get_results()
                
            elif choice == '2':
                # Brute force attack
                max_length = input("Max password length [default: 4]: ").strip() or "4"
                charset_input = input("Charset (lowercase+digits, alpha, custom) [default: lowercase+digits]: ").strip()
                
                if charset_input == 'alpha':
                    import string
                    charset = string.ascii_letters
                elif charset_input == 'custom':
                    charset = input("Enter custom charset: ").strip()
                else:
                    import string
                    charset = string.ascii_lowercase + string.digits
                
                try:
                    max_length = int(max_length)
                    if max_length > 6:
                        print("⚠️  WARNING: Length > 6 may take very long!")
                except ValueError:
                    max_length = 4
                
                show_progress = input("Show progress? (Y/n) [default: Y]: ").strip().lower() != 'n'
                password, attempts = cracker.crack_with_brute_force(max_length, charset, show_progress)
                self.current_results['hash_cracker'] = cracker.get_results()
                
            elif choice == '3':
                # Generate hash
                password = input("Enter password to hash: ").strip()
                hashed = cracker.generate_hash(password)
                print(f"\n{'='*60}")
                print(f"🔐 Hash Generated")
                print(f"{'='*60}")
                print(f"Password: {password}")
                print(f"Hash:     {hashed}")
                print(f"Algorithm: {algorithm.upper()}")
                print(f"{'='*60}\n")
            
            elif choice == '5':
                # Rule-based mutations
                wordlist_file = input("Wordlist file (press Enter for built-in): ").strip()
                if wordlist_file and os.path.exists(wordlist_file):
                    with open(wordlist_file, 'r') as f:
                        wordlist = [line.strip() for line in f if line.strip()]
                else:
                    print("   Using built-in common passwords list...")
                    wordlist = HashCracker.get_common_passwords()
                show_progress = input("Show progress? (Y/n) [default: Y]: ").strip().lower() != 'n'
                password, attempts = cracker.crack_with_rules(wordlist, show_progress=show_progress)
                self.current_results['hash_cracker'] = cracker.get_results()
            
            elif choice == '6':
                # Mask attack
                mask = input("Mask (e.g., ?l?l?l?d) [default: ?l?l?l?d]: ").strip() or "?l?l?l?d"
                show_progress = input("Show progress? (Y/n) [default: Y]: ").strip().lower() != 'n'
                password, attempts = cracker.crack_with_mask(mask, show_progress=show_progress)
                self.current_results['hash_cracker'] = cracker.get_results()
        
        elif choice == '4':
            # Show common passwords
            passwords = HashCracker.get_common_passwords()
            print(f"\n📋 Common Passwords List ({len(passwords)} passwords)")
            print("-" * 40)
            
            # Display in columns
            for i in range(0, min(50, len(passwords)), 5):
                row = passwords[i:i+5]
                print("  ".join(f"{p:15s}" for p in row))
            
            if len(passwords) > 50:
                print(f"\n   ... and {len(passwords) - 50} more")
        
        # Show security tips
        print("\n")
        SecurityTips.display_tips(SecurityTips.get_hash_cracker_tips(),
                                   "🛡️ Hash Security Tips")
    
    # ==================== BRUTE FORCE MODULE ====================
    
    def brute_force_menu(self):
        """Brute Force Login module menu."""
        print("\n" + "="*60)
        print("🔐 BRUTE FORCE LOGIN MODULE")
        print("="*60)
        print("1. Brute force attack")
        print("2. Demo defenses (lockout, rate limiting)")
        print("3. Manage test users")
        print("4. View login history")
        print("0. Back to main menu")
        print("-" * 40)
        
        choice = input("\n👉 Enter choice: ").strip()
        
        if choice == '0':
            return
        
        # Create login system
        login_system = MockLoginSystem()
        brute_force = BruteForceLogin(login_system)
        
        if choice == '1':
            # Brute force attack
            target_user = input("🎯 Target username: ").strip()
            if not target_user:
                print("❌ Username is required!")
                return
            
            password_file = input("Password file (press Enter for built-in): ").strip()
            
            if password_file and os.path.exists(password_file):
                with open(password_file, 'r') as f:
                    password_list = [line.strip() for line in f if line.strip()]
            else:
                print("   Using built-in common passwords list...")
                password_list = HashCracker.get_common_passwords()
            
            show_progress = input("Show progress? (Y/n) [default: Y]: ").strip().lower() != 'n'
            
            password, attempts = brute_force.brute_force_attack(
                target_user, password_list, show_progress
            )
            self.current_results['brute_force'] = brute_force.get_results()
            
        elif choice == '2':
            # Demo defenses
            brute_force.demonstrate_defenses()
            
        elif choice == '3':
            # Manage users
            self._manage_users(login_system)
            
        elif choice == '4':
            # Login history
            username = input("Filter by username (press Enter for all): ").strip()
            limit = input("Number of records [default: 10]: ").strip() or "10"
            
            try:
                limit = int(limit)
            except ValueError:
                limit = 10
            
            history = login_system.get_login_history(username if username else None, limit)
            
            print(f"\n📋 Login History")
            print("-" * 60)
            for i, attempt in enumerate(history, 1):
                print(f"{i}. {attempt['timestamp'][:19]} | {attempt['username']:15s} | "
                      f"{attempt['result']:10s} | {attempt['message']}")
        
        # Show security tips
        print("\n")
        SecurityTips.display_tips(SecurityTips.get_brute_force_tips(),
                                   "🛡️ Brute Force Security Tips")
    
    def _manage_users(self, login_system: MockLoginSystem):
        """Manage test users."""
        print("\n📋 User Management")
        print("-" * 40)
        print("1. List all users")
        print("2. Add new user")
        print("3. View user info")
        print("4. Delete user")
        print("0. Back")
        
        choice = input("\n👉 Enter choice: ").strip()
        
        if choice == '1':
            # List users
            print("\n📋 Registered Users")
            print("-" * 40)
            for username in login_system.users.keys():
                info = login_system.get_user_info(username)
                status = "🔒 LOCKED" if info['locked'] else "✅ Active"
                print(f"  {username:15s} | Failed: {info['failed_attempts']} | {status}")
                
        elif choice == '2':
            # Add user
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            
            if username and password:
                login_system.add_user(username, password)
                print(f"✅ User '{username}' added successfully!")
            else:
                print("❌ Username and password required!")
                
        elif choice == '3':
            # User info
            username = input("Username: ").strip()
            info = login_system.get_user_info(username)
            
            if info:
                print(f"\n📋 User Info: {username}")
                print("-" * 40)
                print(f"  Failed Attempts: {info['failed_attempts']}")
                print(f"  Locked:           {'Yes' if info['locked'] else 'No'}")
                print(f"  Last Login:       {info['last_login'][:19] if info['last_login'] else 'Never'}")
            else:
                print("❌ User not found!")
                
        elif choice == '4':
            # Delete user
            username = input("Username to delete: ").strip()
            if username in login_system.users:
                del login_system.users[username]
                print(f"✅ User '{username}' deleted!")
            else:
                print("❌ User not found!")
    
    # ==================== SECURITY TIPS ====================
    
    def show_security_tips(self):
        """Show security tips menu."""
        print("\n" + "="*60)
        print("🛡️ SECURITY TIPS")
        print("="*60)
        print("1. Port Scanner Tips")
        print("2. Hash Cracker Tips")
        print("3. Brute Force Tips")
        print("4. General Security Tips")
        print("5. All Tips")
        print("0. Back")
        print("-" * 40)
        
        choice = input("\n👉 Enter choice: ").strip()
        
        if choice == '0':
            return
        
        tips_map = {
            '1': (SecurityTips.get_port_scanner_tips, "Port Scanner Security Tips"),
            '2': (SecurityTips.get_hash_cracker_tips, "Hash Cracker Security Tips"),
            '3': (SecurityTips.get_brute_force_tips, "Brute Force Security Tips"),
            '4': (SecurityTips.get_general_tips, "General Security Tips"),
            '5': (None, "All Security Tips")
        }
        
        if choice in tips_map:
            if choice == '5':
                all_tips = SecurityTips.get_all_tips()
                for category, tips in all_tips.items():
                    SecurityTips.display_tips(tips, f"🛡️ {category} Security Tips")
            else:
                tips_func, title = tips_map[choice]
                SecurityTips.display_tips(tips_func(), f"🛡️ {title}")
    
    # ==================== RESULTS ====================
    
    def show_results(self):
        """Show previous results."""
        if not self.current_results:
            print("\n❌ No results available!")
            return
        
        print("\n📊 PREVIOUS RESULTS")
        print("-" * 40)
        
        for module, results in self.current_results.items():
            print(f"\n📌 {module.replace('_', ' ').title()}:")
            print(json.dumps(results, indent=2, default=str))
    
    def export_results(self):
        """Export results to file."""
        if not self.current_results:
            print("\n❌ No results to export!")
            return
        
        print("\n💾 EXPORT RESULTS")
        print("-" * 40)
        print("1. Export to JSON")
        print("2. Export to CSV")
        print("0. Back")
        
        choice = input("\n👉 Enter choice: ").strip()
        
        if choice == '0':
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if choice == '1':
            filename = f"results_{timestamp}.json"
            with open(filename, 'w') as f:
                json.dump(self.current_results, f, indent=2, default=str)
            print(f"\n✅ Results exported to {filename}")
            
        elif choice == '2':
            filename = f"results_{timestamp}.csv"
            self._export_to_csv(filename)
            print(f"\n✅ Results exported to {filename}")
    
    def _export_to_csv(self, filename: str):
        """Export results to CSV format."""
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Module', 'Field', 'Value'])
            
            for module, results in self.current_results.items():
                if isinstance(results, dict):
                    for key, value in results.items():
                        writer.writerow([module, key, value])
    
    # ==================== ABOUT ====================
    
    def show_about(self):
        """Show about information."""
        print("\n" + "="*60)
        print("ℹ️  ABOUT SPTT")
        print("="*60)
        print("""
🔐 Secure Penetration Testing Toolkit (SPTT)
Version: 1.0.0

📚 Educational Purpose Only

This toolkit demonstrates:
• Port scanning techniques
• Hash vulnerability testing  
• Brute-force attack simulation
• Security best practices

⚠️  IMPORTANT WARNINGS:
• Only use on systems you own or have permission to test
• This is for educational/learning purposes only
• Always follow ethical hacking guidelines
• The authors assume no liability for misuse

📖 For more information, see README.md
        """)
        print("="*60 + "\n")
    
    # ==================== MAIN LOOP ====================
    
    def run(self):
        """Run the main dashboard."""
        self.clear_screen()
        self.print_header()
        
        print("""
⚠️  DISCLAIMER:
This toolkit is for EDUCATIONAL PURPOSES ONLY.
Always obtain permission before testing any system.
The authors assume NO LIABILITY for misuse.

Press Enter to continue...""")
        input()
        
        while True:
            self.clear_screen()
            self.print_header()
            self.print_menu()
            
            choice = input("\n👉 Enter your choice: ").strip()
            
            if choice == '0':
                print("\n👋 Thank you for using SPTT!")
                print("Remember: Use your knowledge responsibly! 🛡️\n")
                break
            
            elif choice == '1':
                self.port_scanner_menu()
                
            elif choice == '2':
                self.hash_cracker_menu()
                
            elif choice == '3':
                self.brute_force_menu()
                
            elif choice == '4':
                self.show_security_tips()
                
            elif choice == '5':
                self.show_results()
                input("\nPress Enter to continue...")
                
            elif choice == '6':
                self.export_results()
                input("\nPress Enter to continue...")
                
            elif choice == '7':
                self.show_about()
                input("\nPress Enter to continue...")
            
            elif choice == '8':
                self.launch_web_interface()
            
            elif choice == '9':
                self.utilities_menu()
                
            else:
                print("\n❌ Invalid choice! Please try again.")
                input("\nPress Enter to continue...")


    def launch_web_interface(self):
        """Launch the web interface."""
        try:
            print("\n🌐 Launching web interface at http://localhost:5000 ...")
            import subprocess
            subprocess.Popen([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'web_app.py')])
            print("✅ Web server started. Open http://localhost:5000 in your browser.")
        except Exception as e:
            print(f"\n❌ Failed to launch web interface: {e}")
        input("\nPress Enter to return to the menu...")

    def utilities_menu(self):
        print("\n" + "="*60)
        print("🧰 UTILITIES")
        print("="*60)
        print("1. DNS Tools (resolve/reverse)")
        print("2. HTTP Header Analyzer")
        print("3. Password Strength Audit")
        print("0. Back to main menu")
        print("-" * 40)
        choice = input("\n👉 Enter choice: ").strip()
        if choice == '0':
            return
        if choice == '1':
            from modules import DNSTools
            tool = DNSTools()
            action = input("Action (resolve/reverse) [default: resolve]: ").strip().lower() or "resolve"
            if action == 'reverse':
                ip = input("IP address: ").strip()
                if not ip:
                    print("❌ IP address is required!")
                    return
                hostname = tool.reverse_lookup(ip)
                print("\n" + "="*60)
                print("📄 Reverse DNS")
                print("="*60)
                print(f"IP:       {ip}")
                print(f"Hostname: {hostname or 'Unknown'}")
                print("="*60 + "\n")
            else:
                host = input("Hostname: ").strip()
                if not host:
                    print("❌ Hostname is required!")
                    return
                addrs = tool.resolve_host(host)
                print("\n" + "="*60)
                print("📄 DNS Resolve")
                print("="*60)
                print(f"Hostname: {host}")
                print(f"Addresses: {', '.join(addrs) if addrs else 'None'}")
                print("="*60 + "\n")
            self.current_results['dns_tools'] = tool.get_results()
        elif choice == '2':
            from modules import HTTPAnalyzer
            url = input("URL (e.g., https://example.com): ").strip()
            if not url:
                print("❌ URL is required!")
                return
            analyzer = HTTPAnalyzer(url)
            analyzer.fetch_headers()
            analyzer.analyze()
            res = analyzer.get_results()
            print("\n" + "="*60)
            print("📄 HTTP Header Analysis")
            print("="*60)
            print(f"URL: {res['url']}")
            print("Server:", res['analysis'].get('server'))
            print("Content-Type:", res['analysis'].get('content_type'))
            print("Security Headers:")
            for k, v in res['analysis'].get('security_headers', {}).items():
                print(f"  {k}: {v}")
            print("="*60 + "\n")
            self.current_results['http_analyzer'] = res
        elif choice == '3':
            from modules import PasswordAuditor
            password = input("Password to evaluate: ").strip()
            if not password:
                print("❌ Password is required!")
                return
            auditor = PasswordAuditor()
            res = auditor.evaluate(password)
            print("\n" + "="*60)
            print("📄 Password Strength Audit")
            print("="*60)
            print(f"Score: {res['score']}")
            if res['issues']:
                print("Issues:", ", ".join(res['issues']))
            if res['suggestions']:
                print("Suggestions:", ", ".join(res['suggestions']))
            print("="*60 + "\n")
            self.current_results['password_auditor'] = res
        else:
            print("\n❌ Invalid choice!")
        print("\n")
        SecurityTips.display_tips(SecurityTips.get_general_tips(), "🛡️ General Security Tips")

def main():
    """Main entry point."""
    try:
        import sys
        if not sys.stdin.isatty():
            print("Non-interactive environment detected. Skipping CLI dashboard.")
            print("Use the web interface or import modules programmatically.")
            return
        dashboard = SPTTDashboard()
        dashboard.run()
    except KeyboardInterrupt:
        print("\n\n👋 Program interrupted. Goodbye!")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        try:
            import sys as _sys
            if _sys.stdin.isatty():
                input("\nPress Enter to exit...")
        except EOFError:
            pass


if __name__ == "__main__":
    main()
