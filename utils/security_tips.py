"""
Security Tips Module
Provides security awareness tips for each module
"""

from typing import List, Dict


class SecurityTips:
    """
    Security tips provider for educational purposes.
    """
    
    @staticmethod
    def get_port_scanner_tips() -> List[str]:
        """Get security tips related to port scanning."""
        return [
            "🔒 Close unnecessary ports to reduce attack surface",
            "🛡️ Use a firewall to filter incoming connections",
            "📡 Enable port knocking for additional security",
            "🔐 Use strong authentication for exposed services",
            "📊 Regularly audit open ports on your systems",
            "🚫 Disable unused services completely",
            "🔑 Use VPN for accessing remote services",
            "🌐 Implement network segmentation",
            "📝 Log and monitor port access attempts",
            "🔍 Use intrusion detection systems (IDS)"
        ]
    
    @staticmethod
    def get_hash_cracker_tips() -> List[str]:
        """Get security tips related to hash cracking."""
        return [
            "🔒 Use strong hashing algorithms (bcrypt, scrypt, Argon2)",
            "🧂 Always use unique salts for each password",
            "🔐 Enforce strong password policies",
            "🚫 Don't use weak or common passwords",
            "📊 Implement account lockout after failed attempts",
            "🔢 Use multi-factor authentication (MFA)",
            "🔄 Regularly update and rotate passwords",
            "👀 Monitor for compromised credentials",
            "📚 Educate users about password security",
            "🛡️ Implement password strength meters"
        ]
    
    @staticmethod
    def get_brute_force_tips() -> List[str]:
        """Get security tips related to brute-force attacks."""
        return [
            "🔒 Implement account lockout after failed attempts",
            "⏱️ Use rate limiting to slow down attacks",
            "🔢 Use CAPTCHA for repeated failed attempts",
            "📧 Send alerts for suspicious login attempts",
            "🔐 Enforce strong password policies",
            "🛡️ Use multi-factor authentication (MFA)",
            "📊 Monitor login attempts for patterns",
            "🌐 Use IP blocking for repeated attackers",
            "🔑 Use unique, complex passwords",
            "📱 Implement device fingerprinting"
        ]
    
    @staticmethod
    def get_general_tips() -> List[str]:
        """Get general security tips."""
        return [
            "🔐 Use strong, unique passwords for each account",
            "🛡️ Enable two-factor authentication (2FA) everywhere",
            "📧 Be wary of phishing emails and suspicious links",
            "🔄 Keep all software and systems updated",
            "💾 Regular backups of important data",
            "🌐 Use a reputable VPN on public networks",
            "👤 Practice good password hygiene",
            "📱 Keep your devices locked when unattended",
            "🔍 Review account activity regularly",
            "🛑 Think before sharing personal information online"
        ]
    
    @staticmethod
    def display_tips(tips: List[str], title: str = "🛡️ Security Tips"):
        """Display security tips in a formatted way."""
        print(f"\n{'='*60}")
        print(f"{title}")
        print(f"{'='*60}")
        
        for i, tip in enumerate(tips, 1):
            print(f"  {i}. {tip}")
        
        print(f"{'='*60}\n")
    
    @staticmethod
    def get_all_tips() -> Dict[str, List[str]]:
        """Get all security tips organized by category."""
        return {
            'Port Scanner': SecurityTips.get_port_scanner_tips(),
            'Hash Cracker': SecurityTips.get_hash_cracker_tips(),
            'Brute Force': SecurityTips.get_brute_force_tips(),
            'General': SecurityTips.get_general_tips()
        }
