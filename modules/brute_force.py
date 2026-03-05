"""
Brute Force Login Module
Educational tool for learning about brute-force attacks and login security
"""

import time
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class LoginResult(Enum):
    """Login attempt results."""
    SUCCESS = "success"
    FAILED = "failed"
    LOCKED = "locked"
    RATE_LIMITED = "rate_limited"


@dataclass
class UserAccount:
    """User account with security features."""
    username: str
    password_hash: str
    failed_attempts: int = 0
    locked: bool = False
    lockout_until: Optional[datetime] = None
    last_login: Optional[datetime] = None
    
    def is_locked_out(self) -> bool:
        """Check if account is currently locked out."""
        if not self.locked:
            return False
        if self.lockout_until and datetime.now() > self.lockout_until:
            self.locked = False
            self.failed_attempts = 0
            self.lockout_until = None
            return False
        return True


class MockLoginSystem:
    """
    Mock login system for demonstrating brute-force attacks and defenses.
    """
    
    # Default configuration
    DEFAULT_MAX_ATTEMPTS = 5
    DEFAULT_LOCKOUT_DURATION = 300  # 5 minutes
    DEFAULT_RATE_LIMIT = 3  # Max attempts per minute
    
    def __init__(self, max_attempts: int = None, 
                 lockout_duration: int = None,
                 rate_limit: int = None):
        """
        Initialize the mock login system.
        
        Args:
            max_attempts: Max failed attempts before lockout
            lockout_duration: Lockout duration in seconds
            rate_limit: Max attempts per minute
        """
        self.max_attempts = max_attempts or self.DEFAULT_MAX_ATTEMPTS
        self.lockout_duration = lockout_duration or self.DEFAULT_LOCKOUT_DURATION
        self.rate_limit = rate_limit or self.DEFAULT_RATE_LIMIT
        
        self.users: Dict[str, UserAccount] = {}
        self.login_attempts: List[Dict] = []
        self.rate_limit_tracker: Dict[str, List[datetime]] = {}
        
        # Create default test users
        self._create_default_users()
    
    def _create_default_users(self):
        """Create default test users."""
        default_users = [
            ('admin', 'admin123'),
            ('user', 'password'),
            ('test', 'test123'),
            ('guest', 'guest')
        ]
        
        for username, password in default_users:
            self.add_user(username, password)
    
    def _hash_password(self, password: str) -> str:
        """Hash a password using SHA-256."""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def add_user(self, username: str, password: str):
        """Add a new user to the system."""
        password_hash = self._hash_password(password)
        self.users[username] = UserAccount(
            username=username,
            password_hash=password_hash
        )
    
    def attempt_login(self, username: str, password: str) -> Tuple[LoginResult, str]:
        """
        Attempt to login with username and password.
        
        Args:
            username: Username
            password: Password
            
        Returns:
            Tuple of (LoginResult, message)
        """
        # Check if user exists
        if username not in self.users:
            self._record_attempt(username, LoginResult.FAILED, "User not found")
            return (LoginResult.FAILED, "Invalid username or password")
        
        user = self.users[username]
        
        # Check if account is locked
        if user.is_locked_out():
            remaining_time = (user.lockout_until - datetime.now()).total_seconds()
            self._record_attempt(username, LoginResult.LOCKED, "Account locked")
            return (LoginResult.LOCKED, 
                    f"Account locked. Try again in {int(remaining_time)} seconds")
        
        # Check rate limiting
        if self._check_rate_limit(username):
            self._record_attempt(username, LoginResult.RATE_LIMITED, "Rate limited")
            return (LoginResult.RATE_LIMITED, 
                    f"Too many attempts. Rate limited to {self.rate_limit} per minute")
        
        # Verify password
        password_hash = self._hash_password(password)
        
        if password_hash == user.password_hash:
            # Successful login
            user.failed_attempts = 0
            user.last_login = datetime.now()
            self._record_attempt(username, LoginResult.SUCCESS, "Login successful")
            return (LoginResult.SUCCESS, "Login successful!")
        
        # Failed login
        user.failed_attempts += 1
        
        if user.failed_attempts >= self.max_attempts:
            user.locked = True
            user.lockout_until = datetime.now().timestamp() + self.lockout_duration
            self._record_attempt(username, LoginResult.LOCKED, 
                                f"Account locked after {user.failed_attempts} attempts")
            return (LoginResult.LOCKED, 
                    f"Account locked due to too many failed attempts. "
                    f"Try again in {self.lockout_duration} seconds")
        
        self._record_attempt(username, LoginResult.FAILED, 
                           f"Invalid password. {self.max_attempts - user.failed_attempts} attempts remaining")
        return (LoginResult.FAILED, 
                f"Invalid password. {self.max_attempts - user.failed_attempts} attempts remaining")
    
    def _check_rate_limit(self, username: str) -> bool:
        """Check if user has exceeded rate limit."""
        now = datetime.now()
        
        # Clean old attempts
        if username not in self.rate_limit_tracker:
            self.rate_limit_tracker[username] = []
        
        # Remove attempts older than 1 minute
        self.rate_limit_tracker[username] = [
            t for t in self.rate_limit_tracker[username]
            if (now - t).total_seconds() < 60
        ]
        
        # Check if rate limited
        if len(self.rate_limit_tracker[username]) >= self.rate_limit:
            return True
        
        # Add current attempt
        self.rate_limit_tracker[username].append(now)
        return False
    
    def _record_attempt(self, username: str, result: LoginResult, message: str):
        """Record a login attempt."""
        self.login_attempts.append({
            'username': username,
            'result': result.value,
            'message': message,
            'timestamp': datetime.now()
        })
    
    def get_user_info(self, username: str) -> Optional[Dict]:
        """Get user account information."""
        if username in self.users:
            user = self.users[username]
            return {
                'username': user.username,
                'failed_attempts': user.failed_attempts,
                'locked': user.locked,
                'lockout_until': user.lockout_until.isoformat() if user.lockout_until else None,
                'last_login': user.last_login.isoformat() if user.last_login else None
            }
        return None
    
    def get_login_history(self, username: str = None, limit: int = 10) -> List[Dict]:
        """Get login attempt history."""
        attempts = self.login_attempts
        
        if username:
            attempts = [a for a in attempts if a['username'] == username]
        
        attempts = attempts[-limit:]
        
        return [
            {
                'username': a['username'],
                'result': a['result'],
                'message': a['message'],
                'timestamp': a['timestamp'].isoformat()
            }
            for a in attempts
        ]


class BruteForceLogin:
    """
    Brute Force Login Cracker for educational purposes.
    Demonstrates brute-force login attacks and defenses.
    """
    
    def __init__(self, login_system: MockLoginSystem = None):
        """
        Initialize the brute force login cracker.
        
        Args:
            login_system: Mock login system to attack
        """
        self.login_system = login_system or MockLoginSystem()
        self.attacked_username: Optional[str] = None
        self.found_password: Optional[str] = None
        self.attempts: int = 0
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.attack_successful: bool = False
    
    def brute_force_attack(self, username: str, 
                          password_list: List[str],
                          show_progress: bool = True) -> Tuple[Optional[str], int]:
        """
        Perform brute-force attack on a login system.
        
        Args:
            username: Target username
            password_list: List of passwords to try
            show_progress: Whether to show progress
            
        Returns:
            Tuple of (found_password, total_attempts)
        """
        self.attacked_username = username
        self.attempts = 0
        self.start_time = datetime.now()
        
        print(f"\n{'='*60}")
        print(f"🔓 Brute Force Login Attack")
        print(f"{'='*60}")
        print(f"Target Username: {username}")
        print(f"Password List:   {len(password_list)} passwords")
        print(f"Max Attempts:    {self.login_system.max_attempts}")
        print(f"Lockout After:   {self.login_system.max_attempts} failed attempts")
        print(f"Rate Limit:      {self.login_system.rate_limit} per minute")
        print(f"Start time:      {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")
        
        print("⚠️  WARNING: This is a simulation for educational purposes!")
        print("   Testing against mock login system only.\n")
        
        for i, password in enumerate(password_list):
            self.attempts += 1
            
            result, message = self.login_system.attempt_login(username, password)
            
            if result == LoginResult.SUCCESS:
                self.found_password = password
                self.attack_successful = True
                self.end_time = datetime.now()
                
                print(f"\n{'='*60}")
                print(f"✅ PASSWORD FOUND!")
                print(f"{'='*60}")
                print(f"Username:    {username}")
                print(f"Password:    {password}")
                print(f"Attempts:    {self.attempts}")
                print(f"Time:        {self._get_duration():.2f} seconds")
                print(f"{'='*60}\n")
                
                return (password, self.attempts)
            
            elif result == LoginResult.LOCKED:
                print(f"\n⚠️  Account locked after {self.attempts} attempts!")
                print(f"   {message}")
                break
            
            elif result == LoginResult.RATE_LIMITED:
                print(f"⏳ Rate limited. Waiting...")
                time.sleep(2)
            
            # Show progress
            if show_progress and (i + 1) % 100 == 0:
                print(f"  Progress: {i+1}/{len(password_list)} passwords tried...")
        
        self.end_time = datetime.now()
        
        print(f"\n{'='*60}")
        print(f"❌ PASSWORD NOT FOUND")
        print(f"{'='*60}")
        print(f"Total Attempts: {self.attempts}")
        print(f"Time Elapsed:   {self._get_duration():.2f} seconds")
        print(f"{'='*60}\n")
        
        return (None, self.attempts)
    
    def demonstrate_defenses(self):
        """Demonstrate the defense mechanisms in action."""
        print(f"\n{'='*60}")
        print(f"🛡️ Defense Mechanisms Demonstration")
        print(f"{'='*60}\n")
        
        # Test account lockout
        print("1️⃣  Testing Account Lockout:")
        print("-" * 40)
        
        test_user = "defense_test"
        self.login_system.add_user(test_user, "correct_password")
        
        for i in range(6):
            result, message = self.login_system.attempt_login(test_user, "wrong_password")
            print(f"   Attempt {i+1}: {message}")
        
        # Wait and show unlock
        print(f"\n   Waiting for lockout to expire...")
        time.sleep(1)
        
        result, message = self.login_system.attempt_login(test_user, "correct_password")
        print(f"   After wait: {message}")
        
        # Test rate limiting
        print("\n2️⃣  Testing Rate Limiting:")
        print("-" * 40)
        
        rate_user = "rate_test"
        self.login_system.add_user(rate_user, "password")
        
        for i in range(5):
            result, message = self.login_system.attempt_login(rate_user, "wrong")
            if result == LoginResult.RATE_LIMITED:
                print(f"   Attempt {i+1}: {message}")
                break
            print(f"   Attempt {i+1}: {message}")
        
        print(f"\n{'='*60}\n")
    
    def _get_duration(self) -> float:
        """Get duration of the attack in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        elif self.start_time:
            return (datetime.now() - self.start_time).total_seconds()
        return 0.0
    
    @staticmethod
    def get_security_tips() -> List[str]:
        """
        Get security tips related to brute-force attacks.
        
        Returns:
            List of security tips
        """
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
    
    def get_results(self) -> Dict:
        """
        Get attack results as a dictionary.
        
        Returns:
            Dictionary containing attack results
        """
        return {
            'target_username': self.attacked_username,
            'found_password': self.found_password,
            'attack_successful': self.attack_successful,
            'attempts': self.attempts,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_seconds': self._get_duration()
        }
