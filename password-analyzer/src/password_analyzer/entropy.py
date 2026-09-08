"""
Shannon Entropy calculation and character pool analysis.
"""

import math
import re
from typing import Dict, Tuple


def calculate_entropy(password: str) -> Tuple[float, int, Dict[str, bool]]:
    """
    Calculates Shannon entropy in bits for a given password:
        H = L * log2(R)
    where:
        L = password length
        R = character pool size based on detected character classes.

    Returns:
        Tuple of (entropy_bits, pool_size, charset_flags)
    """
    length = len(password)
    if length == 0:
        return 0.0, 0, {
            "lowercase": False,
            "uppercase": False,
            "digits": False,
            "symbols": False,
            "spaces": False
        }

    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9\s]", password))
    has_space = bool(re.search(r"\s", password))

    pool_size = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digit:
        pool_size += 10
    if has_symbol:
        pool_size += 32
    if has_space:
        pool_size += 1

    # Non-ASCII Unicode characters (emojis, accented characters, etc.)
    non_ascii_count = sum(1 for char in password if ord(char) > 127)
    if non_ascii_count > 0:
        pool_size += 64

    charset_flags = {
        "lowercase": has_lower,
        "uppercase": has_upper,
        "digits": has_digit,
        "symbols": has_symbol,
        "spaces": has_space
    }

    if pool_size == 0:
        return 0.0, 0, charset_flags

    entropy = length * math.log2(pool_size)
    return round(entropy, 2), pool_size, charset_flags
