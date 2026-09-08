"""
Core Password Analyzer coordinating entropy, patterns, and crack time estimation.
"""

from typing import Dict, List, Optional
from .models import AnalysisResult, CrackEstimates, Finding, Severity, StrengthRating
from .entropy import calculate_entropy
from .patterns import detect_patterns, normalize_leetspeak
from .leak_checker import LeakChecker


def estimate_crack_time(entropy_bits: float) -> CrackEstimates:
    """
    Estimates brute-force cracking duration for 3 threat models:
    - Online Throttled (100 attempts/sec, e.g. web form with rate limiting)
    - Fast Single GPU (1 Billion hashes/sec, e.g. MD5/SHA1 on RTX 4090)
    - Nation-State / Dedicated GPU Cluster (1 Trillion hashes/sec)
    """
    # Average combinations needed = 2^(H - 1)
    combinations = 2 ** max(0.0, entropy_bits - 1)

    def format_duration(seconds: float) -> str:
        if seconds < 0.001:
            return "Instant (< 1 millisecond)"
        elif seconds < 1:
            return f"{round(seconds * 1000, 1)} milliseconds"
        elif seconds < 60:
            return f"{round(seconds, 1)} seconds"
        elif seconds < 3600:
            return f"{round(seconds / 60, 1)} minutes"
        elif seconds < 86400:
            return f"{round(seconds / 3600, 1)} hours"
        elif seconds < 31536000:
            return f"{round(seconds / 86400, 1)} days"
        elif seconds < 31536000 * 100:
            return f"{round(seconds / 31536000, 1)} years"
        elif seconds < 31536000 * 1_000_000:
            return f"{round(seconds / (31536000 * 1000), 1)} thousand years"
        elif seconds < 31536000 * 1_000_000_000:
            return f"{round(seconds / (31536000 * 1_000_000), 1)} million years"
        else:
            return "Trillions of years (practically uncrackable)"

    return CrackEstimates(
        online_attack=format_duration(combinations / 100),
        offline_gpu=format_duration(combinations / 1_000_000_000),
        supercomputer_cluster=format_duration(combinations / 1_000_000_000_000)
    )


class PasswordAnalyzer:
    """Orchestrates comprehensive password analysis."""

    def __init__(self, external_leak_file: Optional[str] = None):
        self.leak_checker = LeakChecker(external_file=external_leak_file)

    def analyze(self, password: str) -> AnalysisResult:
        """Executes full analysis pipeline on target password."""
        raw_entropy, pool_size, charset_flags = calculate_entropy(password)
        normalized = normalize_leetspeak(password)

        findings: List[Finding] = []
        total_penalties = 0.0

        # 1. Leak Database Check
        is_leaked, leak_finding, leak_penalty = self.leak_checker.check(password, normalized)
        if leak_finding:
            findings.append(leak_finding)
            total_penalties += leak_penalty

        # 2. Structural Patterns & Dictionary Matching
        pattern_findings, pattern_penalties = detect_patterns(password)
        findings.extend(pattern_findings)
        total_penalties += pattern_penalties

        # 3. Effective Entropy Calculation
        effective_entropy = max(0.0, raw_entropy - total_penalties)
        if is_leaked:
            effective_entropy = min(effective_entropy, 10.0)

        # 4. Strength Rating Determination
        if is_leaked or effective_entropy < 25 or len(password) == 0:
            rating = StrengthRating.VERY_WEAK
            color = "\033[91m"  # Red
        elif effective_entropy < 45 or len(password) < 8:
            rating = StrengthRating.WEAK
            color = "\033[91m"  # Red
        elif effective_entropy < 65:
            rating = StrengthRating.MODERATE
            color = "\033[93m"  # Yellow
        elif effective_entropy < 85:
            rating = StrengthRating.STRONG
            color = "\033[92m"  # Green
        else:
            rating = StrengthRating.VERY_STRONG
            color = "\033[96m"  # Cyan

        reset = "\033[0m"
        colored_rating = f"{color}{rating.value}{reset}"

        # 5. Crack Time Estimates
        crack_estimates = estimate_crack_time(effective_entropy)

        # 6. Actionable Recommendations
        recommendations: List[str] = []
        if is_leaked:
            recommendations.append("CRITICAL: This password has appeared in known data breaches. Do not use it anywhere!")
        if len(password) < 14:
            recommendations.append("Increase length to at least 14-16 characters, or use a 4+ word passphrase.")
        if not charset_flags.get("symbols"):
            recommendations.append("Include special characters (e.g. !@#$%^&*).")
        if not charset_flags.get("digits"):
            recommendations.append("Add numbers dispersed naturally throughout the password.")
        if any("l33tspeak" in f.message for f in findings):
            recommendations.append("Avoid simple character substitutions (e.g. '@' for 'a', '0' for 'o'); cracking software checks these.")
        if any("Sequential" in f.message for f in findings):
            recommendations.append("Avoid keyboard sequences or alphabet runs (e.g. '123', 'qwerty').")

        return AnalysisResult(
            password_masked="*" * len(password),
            length=len(password),
            pool_size=pool_size,
            charset_flags=charset_flags,
            raw_entropy=raw_entropy,
            effective_entropy=round(effective_entropy, 2),
            rating=rating,
            rating_colored=colored_rating,
            findings=findings,
            crack_estimates=crack_estimates,
            recommendations=recommendations
        )
