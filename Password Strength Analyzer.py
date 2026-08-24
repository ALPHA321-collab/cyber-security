#!/usr/bin/env python3
"""
Password Strength Analyzer
- Evaluates password strength based on length, complexity, entropy, and common patterns.
- Generates stronger password/passphrase suggestions.
- Optionally stores salted hashes in SQLite to prevent reuse.
"""

import re
import math
import string
import secrets
import hmac
import hashlib
import os
import sqlite3
from datetime import datetime
from typing import Tuple


class PasswordStrengthAnalyzer:
    """Core password strength evaluation and suggestion logic."""

    def __init__(self, common_passwords: set = None):
        # Small built-in list; in production load a larger file.
        self.common_passwords = common_passwords or {
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'letmein', 'iloveyou', 'admin', 'welcome', 'monkey',
            'password1', '12345678', '111111', '123123', 'sunshine',
            'football', 'princess', 'dragon', 'baseball', 'superman'
        }
        self.common_patterns = [
            'abcdefghijklmnopqrstuvwxyz',
            '0123456789',
            'qwertyuiop',
            'asdfghjkl',
            'zxcvbnm'
        ]

    def _pool_size(self, password: str) -> int:
        """Calculate the character pool size used by the password."""
        pool = 0
        if re.search(r'[a-z]', password):
            pool += 26
        if re.search(r'[A-Z]', password):
            pool += 26
        if re.search(r'\d', password):
            pool += 10
        if re.search(r'[^A-Za-z0-9]', password):
            pool += len(string.punctuation)
        return pool

    def _entropy(self, password: str) -> float:
        """Estimate entropy in bits: length * log2(pool_size)."""
        pool = self._pool_size(password)
        if pool == 0:
            return 0.0
        return len(password) * math.log2(pool)

    def _has_sequential_patterns(self, password: str) -> bool:
        """Check for common keyboard/alphabetic sequences."""
        lower = password.lower()
        for pattern in self.common_patterns:
            lower_pattern = pattern.lower()
            for i in range(len(lower_pattern) - 2):
                seq = lower_pattern[i:i+3]
                if seq in lower or seq[::-1] in lower:
                    return True
        return False

    def evaluate(self, password: str) -> dict:
        """Return a dictionary with score, entropy, category, and feedback."""
        feedback = []
        length = len(password)
        entropy = self._entropy(password)

        # Length score (0–50)
        if length >= 16:
            length_score = 50
        elif length >= 12:
            length_score = 40
        elif length >= 10:
            length_score = 30
        elif length >= 8:
            length_score = 20
        else:
            length_score = 10
            feedback.append("Password is too short. Use at least 12 characters.")

        # Complexity score (0–40)
        classes = 0
        if re.search(r'[a-z]', password):
            classes += 1
        if re.search(r'[A-Z]', password):
            classes += 1
        if re.search(r'\d', password):
            classes += 1
        if re.search(r'[^A-Za-z0-9]', password):
            classes += 1
        complexity_score = classes * 10

        score = length_score + complexity_score

        # Common password penalty
        if password.lower() in self.common_passwords:
            score = min(score, 20)
            feedback.append("This is a very common password and can be guessed easily.")

        # Sequential pattern penalty
        if self._has_sequential_patterns(password):
            score = max(0, score - 20)
            feedback.append("Avoid sequential characters (e.g., 'abc', '123').")

        # Repeated characters penalty
        unique_ratio = len(set(password)) / length if length > 0 else 0
        if unique_ratio < 0.6:
            score = max(0, score - 10)
            feedback.append("Too many repeated characters.")

        # Clamp score to 0–100
        score = max(0, min(100, score))

        # Category
        if score >= 80 and entropy >= 60:
            category = "Very Strong"
        elif score >= 60:
            category = "Strong"
        elif score >= 40:
            category = "Fair"
        elif score >= 20:
            category = "Weak"
        else:
            category = "Very Weak"

        return {
            'score': score,
            'entropy_bits': round(entropy, 1),
            'length': length,
            'character_classes': classes,
            'category': category,
            'feedback': feedback
        }

    def suggest_stronger(self, length: int = 16) -> str:
        """Generate a cryptographically secure random password."""
        if length < 12:
            length = 12
        alphabet = string.ascii_letters + string.digits + string.punctuation

        while True:
            candidate = ''.join(secrets.choice(alphabet) for _ in range(length))
            if (any(c.islower() for c in candidate) and
                any(c.isupper() for c in candidate) and
                any(c.isdigit() for c in candidate) and
                any(c in string.punctuation for c in candidate)):
                return candidate

    def suggest_passphrase(self, word_count: int = 4) -> str:
        """Suggest a memorable passphrase from a small wordlist."""
        sample_words = [
            'apple', 'tiger', 'river', 'stone', 'cloud', 'flame',
            'ocean', 'night', 'music', 'green', 'happy', 'light'
        ]
        return '-'.join(secrets.choice(sample_words) for _ in range(word_count))


class PasswordHistoryDB:
    """Stores salted password hashes to prevent reuse (no plain text)."""

    def __init__(self, db_path: str = 'password_history.db'):
        self.conn = sqlite3.connect(db_path)
        self.cur = self.conn.cursor()
        self.cur.execute('''
            CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password_hash BLOB NOT NULL,
                salt BLOB NOT NULL,
                created_at TEXT NOT NULL
            )
        ''')
        self.conn.commit()

    @staticmethod
    def hash_password(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """Hash password using PBKDF2-HMAC-SHA256 with a random salt."""
        if salt is None:
            salt = os.urandom(16)
        digest = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            310_000  # iterations – slows brute force
        )
        return digest, salt

    def store_password(self, username: str, password: str):
        """Store salted hash of the password."""
        digest, salt = self.hash_password(password)
        self.cur.execute(
            'INSERT INTO password_history (username, password_hash, salt, created_at) VALUES (?, ?, ?, ?)',
            (username, digest, salt, datetime.utcnow().isoformat())
        )
        self.conn.commit()

    def is_reused(self, username: str, password: str) -> bool:
        """Check if candidate password matches any historical hash."""
        self.cur.execute(
            'SELECT password_hash, salt FROM password_history WHERE username = ?',
            (username,)
        )
        for stored_hash, salt in self.cur.fetchall():
            candidate_hash, _ = self.hash_password(password, salt)
            if hmac.compare_digest(candidate_hash, stored_hash):
                return True
        return False

    def close(self):
        self.conn.close()


def main():
    """Command-line interface for the analyzer."""
    analyzer = PasswordStrengthAnalyzer()
    password = input("Enter a password to analyze: ")

    result = analyzer.evaluate(password)

    print(f"\nScore: {result['score']}/100")
    print(f"Category: {result['category']}")
    print(f"Entropy: {result['entropy_bits']} bits")
    print(f"Length: {result['length']}, Character classes: {result['character_classes']}")

    if result['feedback']:
        print("Feedback:")
        for item in result['feedback']:
            print(f" - {item}")

    if result['score'] < 60:
        print("\nSuggested stronger password:", analyzer.suggest_stronger())
        print("Suggested passphrase:", analyzer.suggest_passphrase())

    # Optional history check (only if user wants to store/check)
    use_history = input("\nDo you want to check/store password history? (y/n): ").strip().lower()
    if use_history == 'y':
        db = PasswordHistoryDB()
        username = input("Enter username: ")
        if db.is_reused(username, password):
            print("This password has been used before. Please choose a different one.")
        else:
            db.store_password(username, password)
            print("Password stored securely (salted hash).")
        db.close()


if __name__ == "__main__":
    main()