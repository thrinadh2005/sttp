from typing import Dict, List, Optional
from datetime import datetime
import re


class PasswordAuditor:
    def __init__(self):
        self.password: Optional[str] = None
        self.score: int = 0
        self.issues: List[str] = []
        self.suggestions: List[str] = []
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

    def evaluate(self, password: str) -> Dict:
        self.start_time = datetime.now()
        self.password = password
        self.score = 0
        self.issues = []
        self.suggestions = []

        length = len(password)
        has_lower = bool(re.search(r"[a-z]", password))
        has_upper = bool(re.search(r"[A-Z]", password))
        has_digit = bool(re.search(r"\d", password))
        has_symbol = bool(re.search(r"[^\w\s]", password))
        repeated = bool(re.search(r"(.)\1{2,}", password))
        sequential = bool(re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef)", password.lower()))
        common = password.lower() in {
            "password", "123456", "qwerty", "letmein", "admin", "welcome", "iloveyou", "monkey", "dragon", "football"
        }

        self.score += min(length, 20)
        self.score += 10 if has_lower else 0
        self.score += 10 if has_upper else 0
        self.score += 10 if has_digit else 0
        self.score += 15 if has_symbol else 0
        self.score -= 15 if repeated else 0
        self.score -= 15 if sequential else 0
        self.score -= 25 if common else 0
        self.score = max(self.score, 0)

        if length < 12:
            self.issues.append("too_short")
            self.suggestions.append("use_at_least_12_characters")
        if not has_upper:
            self.issues.append("missing_uppercase")
            self.suggestions.append("add_uppercase_letters")
        if not has_lower:
            self.issues.append("missing_lowercase")
            self.suggestions.append("add_lowercase_letters")
        if not has_digit:
            self.issues.append("missing_digits")
            self.suggestions.append("include_numbers")
        if not has_symbol:
            self.issues.append("missing_symbols")
            self.suggestions.append("add_special_characters")
        if repeated:
            self.issues.append("repeated_characters")
            self.suggestions.append("avoid_repeating_characters")
        if sequential:
            self.issues.append("sequential_patterns")
            self.suggestions.append("avoid_sequential_patterns")
        if common:
            self.issues.append("common_password")
            self.suggestions.append("avoid_common_passwords")

        self.end_time = datetime.now()

        return self.get_results()

    def get_results(self) -> Dict:
        return {
            "password": self.password,
            "score": self.score,
            "issues": self.issues,
            "suggestions": self.suggestions,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else None,
        }
