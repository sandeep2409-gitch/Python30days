"""Data models for breach checking results and metadata."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Status(str, Enum):
    CLEAN = "CLEAN"
    BREACHED = "BREACHED"
    ERROR = "ERROR"


@dataclass
class BreachRecord:
    """Represents an individual breach exposure."""
    name: str
    title: Optional[str] = None
    domain: Optional[str] = None
    breach_date: Optional[str] = None
    pwn_count: Optional[int] = None
    data_classes: List[str] = field(default_factory=list)
    description: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "title": self.title,
            "domain": self.domain,
            "breach_date": self.breach_date,
            "pwn_count": self.pwn_count,
            "data_classes": self.data_classes,
            "description": self.description,
        }


@dataclass
class CheckResult:
    """Represents the lookup outcome for a single email or username."""
    account: str
    provider: str
    status: Status
    breaches: List[BreachRecord] = field(default_factory=list)
    error_message: Optional[str] = None
    response_time: float = 0.0

    @property
    def is_breached(self) -> bool:
        return self.status == Status.BREACHED

    @property
    def breach_count(self) -> int:
        return len(self.breaches)

    def to_dict(self) -> dict:
        return {
            "account": self.account,
            "provider": self.provider,
            "status": self.status.value,
            "breach_count": self.breach_count,
            "breaches": [b.to_dict() for b in self.breaches],
            "error_message": self.error_message,
            "response_time": round(self.response_time, 3),
        }


@dataclass
class ScanSummary:
    """Aggregated metrics across single or batch lookups."""
    total: int = 0
    breached: int = 0
    clean: int = 0
    errors: int = 0
    duration_seconds: float = 0.0
    results: List[CheckResult] = field(default_factory=list)

    def add_result(self, result: CheckResult) -> None:
        self.results.append(result)
        self.total += 1
        if result.status == Status.BREACHED:
            self.breached += 1
        elif result.status == Status.CLEAN:
            self.clean += 1
        else:
            self.errors += 1

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "breached": self.breached,
            "clean": self.clean,
            "errors": self.errors,
            "duration_seconds": round(self.duration_seconds, 2),
            "results": [r.to_dict() for r in self.results],
        }

