"""
Password Strength Analyzer & Shannon Entropy Calculator.
"""

from .analyzer import PasswordAnalyzer, estimate_crack_time
from .entropy import calculate_entropy
from .models import AnalysisResult, CrackEstimates, Finding, Severity, StrengthRating
from .patterns import detect_patterns, normalize_leetspeak
from .main import main

__version__ = "0.1.0"
__all__ = [
    "PasswordAnalyzer",
    "calculate_entropy",
    "detect_patterns",
    "normalize_leetspeak",
    "estimate_crack_time",
    "AnalysisResult",
    "CrackEstimates",
    "Finding",
    "Severity",
    "StrengthRating",
    "main",
]
