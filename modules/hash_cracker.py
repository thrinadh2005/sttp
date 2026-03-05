"""
Hash Cracker Module
Educational tool for learning about hash vulnerabilities and password security
"""

import hashlib
import time
import string
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from itertools import product


class HashCracker:
    """
    Hash Cracker Module for educational purposes.
    Demonstrates hash vulnerability testing using dictionary and brute-force methods.
    """
    
    # Supported hash algorithms
    SUPPORTED_ALGORITHMS = ['md5', 'sha1', 'sha256', 'sha512', 'sha3_256']
    
    def __init__(self, hash_value: str, algorithm: str = 'md5'):
        """
        Initialize the hash cracker.
        
        Args:
            hash_value: The hash value to crack
            algorithm: Hash algorithm (md5, sha1, sha256)
        """
        self.target_hash = hash_value.lower().strip()
        self.algorithm = algorithm.lower()
        self.found_password: Optional[str] = None
        self.attempts: int = 0
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        
        if self.algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm. Choose from: {self.SUPPORTED_ALGORITHMS}")
    
    def _hash_password(self, password: str) -> str:
        """
        Hash a password using the specified algorithm.
        
        Args:
            password: Password to hash
            
        Returns:
            Hexadecimal hash string
        """
        password_bytes = password.encode('utf-8')
        
        if self.algorithm == 'md5':
            return hashlib.md5(password_bytes).hexdigest()
        elif self.algorithm == 'sha1':
            return hashlib.sha1(password_bytes).hexdigest()
        elif self.algorithm == 'sha256':
            return hashlib.sha256(password_bytes).hexdigest()
        elif self.algorithm == 'sha512':
            return hashlib.sha512(password_bytes).hexdigest()
        elif self.algorithm == 'sha3_256':
            return hashlib.sha3_256(password_bytes).hexdigest()
        
        return ""
    
    def crack_with_dictionary(self, wordlist: List[str], 
                              show_progress: bool = True) -> Tuple[Optional[str], int]:
        """
        Crack hash using dictionary attack.
        
        Args:
            wordlist: List of passwords to try
            show_progress: Whether to show progress
            
        Returns:
            Tuple of (found_password, total_attempts)
        """
        self.start_time = datetime.now()
        self.attempts = 0
        
        print(f"\n{'='*60}")
        print(f"🔓 Dictionary Attack - {self.algorithm.upper()}")
        print(f"{'='*60}")
        print(f"Target Hash: {self.target_hash}")
        print(f"Wordlist Size: {len(wordlist)} passwords")
        print(f"Start time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")
        
        for i, password in enumerate(wordlist):
            self.attempts += 1
            password = password.strip()
            
            # Hash the password and compare
            hashed = self._hash_password(password)
            
            if hashed == self.target_hash:
                self.found_password = password
                self.end_time = datetime.now()
                
                print(f"\n{'='*60}")
                print(f"✅ PASSWORD FOUND!")
                print(f"{'='*60}")
                print(f"Password:    {password}")
                print(f"Hash:        {hashed}")
                print(f"Attempts:    {self.attempts}")
                print(f"Time:        {self._get_duration():.2f} seconds")
                print(f"{'='*60}\n")
                
                return (password, self.attempts)
            
            # Show progress
            if show_progress and (i + 1) % 1000 == 0:
                print(f"  Progress: {i+1}/{len(wordlist)} passwords tried...")
        
        self.end_time = datetime.now()
        
        print(f"\n{'='*60}")
        print(f"❌ PASSWORD NOT FOUND IN WORDLIST")
        print(f"{'='*60}")
        print(f"Total Attempts: {self.attempts}")
        print(f"Time Elapsed:   {self._get_duration():.2f} seconds")
        print(f"{'='*60}\n")
        
        return (None, self.attempts)
    
    def crack_with_brute_force(self, max_length: int = 4,
                               charset: str = None,
                               show_progress: bool = True) -> Tuple[Optional[str], int]:
        """
        Crack hash using brute-force attack.
        
        Args:
            max_length: Maximum password length to try
            charset: Character set to use (default: lowercase + digits)
            show_progress: Whether to show progress
            
        Returns:
            Tuple of (found_password, total_attempts)
        """
        if charset is None:
            charset = string.ascii_lowercase + string.digits
        
        self.start_time = datetime.now()
        self.attempts = 0
        
        # Calculate total combinations
        total_combinations = sum(len(charset) ** i for i in range(1, max_length + 1))
        
        print(f"\n{'='*60}")
        print(f"🔓 Brute Force Attack - {self.algorithm.upper()}")
        print(f"{'='*60}")
        print(f"Target Hash:  {self.target_hash}")
        print(f"Max Length:   {max_length}")
        print(f"Charset:      {charset}")
        print(f"Total Combos: ~{total_combinations:,} (estimated)")
        print(f"Start time:   {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")
        
        print("⚠️  WARNING: Brute force can take very long for longer passwords!")
        print("   Press Ctrl+C to stop...\n")
        
        try:
            for length in range(1, max_length + 1):
                if show_progress:
                    print(f"  Trying length {length}...")
                
                for password in product(charset, repeat=length):
                    self.attempts += 1
                    password_str = ''.join(password)
                    
                    hashed = self._hash_password(password_str)
                    
                    if hashed == self.target_hash:
                        self.found_password = password_str
                        self.end_time = datetime.now()
                        
                        print(f"\n{'='*60}")
                        print(f"✅ PASSWORD FOUND!")
                        print(f"{'='*60}")
                        print(f"Password:    {password_str}")
                        print(f"Hash:        {hashed}")
                        print(f"Attempts:    {self.attempts:,}")
                        print(f"Time:        {self._get_duration():.2f} seconds")
                        print(f"{'='*60}\n")
                        
                        return (password_str, self.attempts)
                    
                    # Progress update
                    if show_progress and self.attempts % 10000 == 0:
                        print(f"  Progress: {self.attempts:,} attempts...")
        
        except KeyboardInterrupt:
            print("\n\n⚠️  Brute force interrupted by user!")
        
        self.end_time = datetime.now()
        
        print(f"\n{'='*60}")
        print(f"❌ PASSWORD NOT FOUND")
        print(f"{'='*60}")
        print(f"Total Attempts: {self.attempts:,}")
        print(f"Time Elapsed:  {self._get_duration():.2f} seconds")
        print(f"{'='*60}\n")
        
        return (None, self.attempts)
    
    def _get_duration(self) -> float:
        """Get duration of the attack in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        elif self.start_time:
            return (datetime.now() - self.start_time).total_seconds()
        return 0.0
    
    def generate_hash(self, password: str) -> str:
        """
        Generate hash for a password.
        
        Args:
            password: Password to hash
            
        Returns:
            Hash string
        """
        return self._hash_password(password)
    
    def crack_with_rules(self, wordlist: List[str],
                         suffixes: List[str] = None,
                         prefixes: List[str] = None,
                         show_progress: bool = True) -> Tuple[Optional[str], int]:
        """
        Crack hash using rule-based mutations on a dictionary.
        
        Args:
            wordlist: Base words to mutate
            suffixes: Suffixes to append
            prefixes: Prefixes to prepend
            show_progress: Whether to show progress
        """
        if suffixes is None:
            suffixes = ['1', '123', '!', '2024']
        if prefixes is None:
            prefixes = ['!', '@', '#']
        
        subs = {'a': ['a', '@'], 'e': ['e', '3'], 'i': ['i', '1'], 'o': ['o', '0'], 's': ['s', '$', '5']}
        
        self.start_time = datetime.now()
        self.attempts = 0
        
        print(f"\n{'='*60}")
        print(f"🔓 Rule-Based Attack - {self.algorithm.upper()}")
        print(f"{'='*60}")
        print(f"Target Hash: {self.target_hash}")
        print(f"Base Words:  {len(wordlist)}")
        print(f"Start time:  {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")
        
        def variants(word: str) -> List[str]:
            v = set()
            w = word.strip()
            v.add(w)
            v.update(w + s for s in suffixes)
            v.update(p + w for p in prefixes)
            w_sub = ''.join(subs.get(ch, [ch])[1] if ch in subs else ch for ch in w)
            v.add(w_sub)
            v.update(w_sub + s for s in suffixes)
            v.update(p + w_sub for p in prefixes)
            return list(v)
        
        count = 0
        for i, base in enumerate(wordlist):
            for cand in variants(base):
                self.attempts += 1
                if self._hash_password(cand) == self.target_hash:
                    self.found_password = cand
                    self.end_time = datetime.now()
                    print(f"\n{'='*60}")
                    print(f"✅ PASSWORD FOUND!")
                    print(f"{'='*60}")
                    print(f"Password:    {cand}")
                    print(f"Attempts:    {self.attempts}")
                    print(f"Time:        {self._get_duration():.2f} seconds")
                    print(f"{'='*60}\n")
                    return (cand, self.attempts)
                count += 1
                if show_progress and count % 5000 == 0:
                    print(f"  Progress: {count:,} candidates tried...")
        
        self.end_time = datetime.now()
        print(f"\n{'='*60}")
        print(f"❌ PASSWORD NOT FOUND")
        print(f"{'='*60}")
        print(f"Total Attempts: {self.attempts:,}")
        print(f"Time Elapsed:  {self._get_duration():.2f} seconds")
        print(f"{'='*60}\n")
        return (None, self.attempts)
    
    def crack_with_mask(self, mask: str,
                        show_progress: bool = True) -> Tuple[Optional[str], int]:
        """
        Crack hash using a simple mask pattern.
        
        Mask tokens: ?l (lower), ?u (upper), ?d (digits)
        Example: ?l?l?l?d
        """
        token_map = {
            '?l': string.ascii_lowercase,
            '?u': string.ascii_uppercase,
            '?d': string.digits
        }
        tokens = [mask[i:i+2] for i in range(0, len(mask), 2)]
        charsets = []
        for t in tokens:
            if t in token_map:
                charsets.append(token_map[t])
            else:
                return (None, 0)
        
        self.start_time = datetime.now()
        self.attempts = 0
        
        total = 1
        for cs in charsets:
            total *= len(cs)
        
        print(f"\n{'='*60}")
        print(f"🔓 Mask Attack - {self.algorithm.upper()}")
        print(f"{'='*60}")
        print(f"Target Hash:  {self.target_hash}")
        print(f"Mask:         {mask}")
        print(f"Total Combos: ~{total:,} (estimated)")
        print(f"Start time:   {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")
        
        idx = 0
        for combo in product(*charsets):
            self.attempts += 1
            cand = ''.join(combo)
            if self._hash_password(cand) == self.target_hash:
                self.found_password = cand
                self.end_time = datetime.now()
                print(f"\n{'='*60}")
                print(f"✅ PASSWORD FOUND!")
                print(f"{'='*60}")
                print(f"Password:    {cand}")
                print(f"Attempts:    {self.attempts:,}")
                print(f"Time:        {self._get_duration():.2f} seconds")
                print(f"{'='*60}\n")
                return (cand, self.attempts)
            idx += 1
            if show_progress and idx % 10000 == 0:
                print(f"  Progress: {idx:,} attempts...")
        
        self.end_time = datetime.now()
        print(f"\n{'='*60}")
        print(f"❌ PASSWORD NOT FOUND")
        print(f"{'='*60}")
        print(f"Total Attempts: {self.attempts:,}")
        print(f"Time Elapsed:  {self._get_duration():.2f} seconds")
        print(f"{'='*60}\n")
        return (None, self.attempts)
    
    @staticmethod
    def get_common_passwords() -> List[str]:
        """
        Get a list of common passwords for testing.
        
        Returns:
            List of common passwords
        """
        return [
            '123456', 'password', '12345678', 'qwerty', '123456789',
            '12345', '1234', '111111', '1234567', 'dragon',
            '123123', 'baseball', 'abc123', 'football', 'monkey',
            'letmein', 'shadow', 'master', '666666', 'qwertyuiop',
            '123321', 'mustang', '1234567890', 'michael', '654321',
            'superman', '1qaz2wsx', '7777777', '121212', '000000',
            'qazwsx', '123qwe', 'killer', 'trustno1', 'jordan',
            'jennifer', 'zxcvbnm', 'asdfgh', 'hunter', 'buster',
            'soccer', 'harley', 'batman', 'andrew', 'tigger',
            'sunshine', 'iloveyou', '2000', 'charlie', 'robert',
            'thomas', 'hockey', 'ranger', 'daniel', 'starwars',
            'klaster', '112233', 'george', 'computer', 'michelle',
            'jessica', 'pepper', '1111', 'zxcvbn', '555555',
            '11111111', '131313', 'freedom', '777777', 'pass',
            'maggie', '159753', 'aaaaaa', 'ginger', 'princess',
            'joshua', 'cheese', 'amanda', 'summer', 'love',
            'ashley', 'nicole', 'chelsea', 'biteme', 'matthew',
            'access', 'yankees', '987654321', 'dallas', 'austin',
            'thunder', 'taylor', 'matrix', 'mobilemail', 'mom',
            'monitor', 'monitoring', 'montana', 'moon', 'moscow'
        ]
    
    @staticmethod
    def get_security_tips() -> List[str]:
        """
        Get security tips related to hash cracking.
        
        Returns:
            List of security tips
        """
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
    
    def get_results(self) -> Dict:
        """
        Get crack results as a dictionary.
        
        Returns:
            Dictionary containing crack results
        """
        return {
            'algorithm': self.algorithm,
            'target_hash': self.target_hash,
            'found_password': self.found_password,
            'attempts': self.attempts,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_seconds': self._get_duration()
        }
