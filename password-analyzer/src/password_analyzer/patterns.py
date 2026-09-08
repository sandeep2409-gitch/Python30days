"""
Pattern detection: Keyboard walks, sequential characters, repetitions,
l33tspeak normalization, and dictionary matching.
"""

import re
from typing import Dict, List, Set, Tuple
from .models import Finding, Severity

# Common keyboard patterns and alphabetic sequences (both directions)
KEYBOARD_SEQUENCES: List[str] = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890", "0987654321",
    "abcdefghijklmnopqrstuvwxyz",
    "zyxwvutsrqponmlkjihgfedcba",
    "qazwsxedcrfvtgbyhnujmikolp"
]

# Common dictionary words often used in weak passwords
COMMON_DICTIONARY_WORDS: Set[str] = {
    "password", "admin", "welcome", "login", "user", "root", "master",
    "access", "secret", "system", "security", "service", "server",
    "client", "guest", "default", "test", "demo", "oracle", "cisco",
    "dragon", "monkey", "shadow", "orange", "summer", "winter", "spring",
    "autumn", "flower", "super", "coffee", "guitar", "matrix", "player",
    "yellow", "purple", "hunter", "silver", "golden", "magic", "rocket",
    "family", "friend", "school", "office", "doctor", "police", "street",
    "planet", "star", "ocean", "river", "mountain", "forest", "castle",
    "football", "baseball", "hockey", "soccer", "basketball", "tennis",
    "superman", "batman", "spiderman", "ironman", "avengers", "trustno1"
}

# L33tspeak substitution mappings
LEET_MAPPINGS: Dict[str, str] = {
    "@": "a", "4": "a", "^": "a",
    "8": "b", "6": "b",
    "(": "c", "<": "c", "{": "c", "[": "c",
    "3": "e", "€": "e",
    "9": "g",
    "#": "h",
    "1": "i", "!": "i", "|": "i", "l": "i",
    "0": "o", "()": "o",
    "5": "s", "$": "s", "z": "s",
    "7": "t", "+": "t",
    "v": "u", "µ": "u",
    "2": "z"
}


def normalize_leetspeak(text: str) -> str:
    """Translates common l33tspeak substitutions into plain lowercase english."""
    lower_text = text.lower()
    return "".join(LEET_MAPPINGS.get(char, char) for char in lower_text)


def detect_patterns(password: str) -> Tuple[List[Finding], float]:
    """
    Analyzes password for structural flaws, predictable keyboard patterns,
    repeated characters, and embedded dictionary words.

    Returns:
        Tuple of (findings_list, total_penalty_points)
    """
    findings: List[Finding] = []
    penalties: float = 0.0
    length = len(password)
    lower_pwd = password.lower()
    norm_pwd = normalize_leetspeak(password)

    # 1. Length evaluations
    if length < 8:
        findings.append(Finding(
            severity=Severity.CRITICAL,
            message=f"Password is too short ({length} chars). Minimum recommended is 12-16."
        ))
        penalties += 25.0
    elif length < 12:
        findings.append(Finding(
            severity=Severity.WARNING,
            message=f"Length ({length} chars) is acceptable for low-risk, but 14+ is recommended."
        ))
        penalties += 10.0
    else:
        findings.append(Finding(
            severity=Severity.GOOD,
            message=f"Strong length ({length} characters)."
        ))

    # 2. Repeated character sequences (e.g. 'aaa', '1111', '$$$')
    repeat_match = re.search(r"(.)\1{2,}", password)
    if repeat_match:
        findings.append(Finding(
            severity=Severity.WARNING,
            message=f"Contains repeated character sequence: '{repeat_match.group(0)}'."
        ))
        penalties += 12.0

    # 3. Low character diversity ratio
    if length >= 6:
        unique_chars = len(set(password))
        diversity_ratio = unique_chars / length
        if diversity_ratio < 0.45:
            findings.append(Finding(
                severity=Severity.WARNING,
                message=f"Low character diversity ({unique_chars} unique chars out of {length})."
            ))
            penalties += 10.0

    # 4. Sequential keyboard walks / sequences (e.g., '123', 'abc', 'qwerty')
    detected_sequences: List[str] = []
    for seq in KEYBOARD_SEQUENCES:
        for i in range(len(seq) - 2):
            sub = seq[i:i + 3]
            if sub in lower_pwd:
                detected_sequences.append(sub)

    if detected_sequences:
        unique_seqs = sorted(list(set(detected_sequences)))[:3]
        findings.append(Finding(
            severity=Severity.WARNING,
            message=f"Sequential keyboard/alphabet pattern detected: {', '.join(unique_seqs)}"
        ))
        penalties += 15.0

    # 5. Dictionary words & L33tspeak matching
    detected_words: List[str] = []
    for word in COMMON_DICTIONARY_WORDS:
        if len(word) >= 4:
            if word in lower_pwd:
                detected_words.append(word)
            elif word in norm_pwd:
                detected_words.append(f"{word} (via l33tspeak substitution)")

    if detected_words:
        unique_words = sorted(list(set(detected_words)))[:3]
        findings.append(Finding(
            severity=Severity.WARNING,
            message=f"Contains common dictionary word(s): {', '.join(unique_words)}"
        ))
        penalties += 15.0

    return findings, penalties
