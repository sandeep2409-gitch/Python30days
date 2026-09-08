"""
Data models and dataclasses for password analysis.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class Severity(str, Enum):
    GOOD = "GOOD"
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class StrengthRating(str, Enum):
    VERY_WEAK = "VERY WEAK"
    WEAK = "WEAK"
    MODERATE = "MODERATE"
    STRONG = "STRONG"
    VERY_STRONG = "VERY STRONG"


@dataclass
class Finding:
    severity: Severity
    message: str


@dataclass
class CrackEstimates:
    online_attack: str           # e.g., 100 guesses/sec (throttled login)
    offline_gpu: str             # e.g., 10^9 hashes/sec (single modern GPU)
    supercomputer_cluster: str   # e.g., 10^12 hashes/sec (dedicated GPU rig)


@dataclass
class AnalysisResult:
    password_masked: str
    length: int
    pool_size: int
    charset_flags: Dict[str, bool]
    raw_entropy: float
    effective_entropy: float
    rating: StrengthRating
    rating_colored: str
    findings: List[Finding] = field(default_factory=list)
    crack_estimates: Optional[CrackEstimates] = None
    recommendations: List[str] = field(default_factory=list)
