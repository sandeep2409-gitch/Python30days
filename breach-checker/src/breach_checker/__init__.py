"""Breach Checker package."""

from breach_checker.client import HIBPClient, XposedOrNotClient, get_client
from breach_checker.main import main
from breach_checker.models import BreachRecord, CheckResult, ScanSummary, Status
from breach_checker.scanner import export_results, load_targets_from_file, scan_targets

__all__ = [
    "main",
    "get_client",
    "BaseBreachClient",
    "XposedOrNotClient",
    "HIBPClient",
    "BreachRecord",
    "CheckResult",
    "ScanSummary",
    "Status",
    "load_targets_from_file",
    "scan_targets",
    "export_results",
]

__version__ = "0.1.0"
