"""
Leak and breach database checker (RockYou style).
"""

from pathlib import Path
import sys
from typing import Optional, Set, Tuple
from .models import Finding, Severity

# Top frequently breached passwords from real-world breaches (RockYou/HaveIBeenPwned top lists)
TOP_BREACHED_PASSWORDS: Set[str] = {
    "123456", "password", "123456789", "12345678", "12345", "111111",
    "1234567", "sunshine", "qwerty", "iloveyou", "princess", "admin",
    "welcome", "football", "monkey", "charlie", "donald", "password1",
    "secret", "letmein", "master", "dragon", "starwars", "solo",
    "hockey", "baseball", "superman", "batman", "killer", "trustno1",
    "ninja", "shadow", "michael", "jessica", "mustang", "ashley",
    "thomas", "chelsea", "hunter", "liverpool", "arsenal", "jordan",
    "matrix", "robert", "daniel", "carlos", "ginger", "system",
    "whatever", "cheese", "cookie", "summer", "winter", "passcode",
    "computer", "internet", "security", "access", "testing", "pass123",
    "root", "guest", "default", "changeme", "hello", "orange", "000000",
    "login", "super", "123123", "654321", "asdfgh", "qwertyuiop"
}


class LeakChecker:
    """Checks passwords against an in-memory set of leaked breach passwords."""

    def __init__(self, external_file: Optional[str] = None):
        self.breach_set: Set[str] = set(TOP_BREACHED_PASSWORDS)
        if external_file:
            self.load_external_file(external_file)

    def load_external_file(self, filepath: str) -> int:
        """Loads additional leaked passwords from a plaintext file (one per line)."""
        path = Path(filepath)
        count = 0
        if not path.is_file():
            print(f"[Warning] Leak database '{filepath}' not found.", file=sys.stderr)
            return count

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    entry = line.strip().lower()
                    if entry:
                        self.breach_set.add(entry)
                        count += 1
        except Exception as e:
            print(f"[Warning] Failed loading leak database: {e}", file=sys.stderr)
        return count

    def check(self, password: str, normalized_password: str) -> Tuple[bool, Optional[Finding], float]:
        """
        Checks if the exact password or its l33tspeak normalized version
        exists in the breach database.
        """
        pwd_lower = password.lower()
        norm_lower = normalized_password.lower()

        if pwd_lower in self.breach_set or norm_lower in self.breach_set:
            finding = Finding(
                severity=Severity.CRITICAL,
                message="Password matches a known leaked password from public breaches (e.g. RockYou)!"
            )
            return True, finding, 50.0

        return False, None, 0.0
