"""
Terminal output formatters and JSON exporters.
"""

import json
from typing import Any, Dict, List, Tuple
from .models import AnalysisResult, Severity


def format_single_report(password: str, result: AnalysisResult, show_cleartext: bool = False) -> str:
    """Formats a rich single-password analysis report for the console."""
    display_pwd = password if show_cleartext else result.password_masked
    active_sets = [k for k, v in result.charset_flags.items() if v]

    lines = [
        "",
        "=" * 65,
        " 🔐 PASSWORD STRENGTH & ENTROPY REPORT",
        "=" * 65,
        f" Target Password   : {display_pwd}",
        f" Length            : {result.length} characters",
        f" Character Pool    : {result.pool_size} possible characters",
        f" Character Classes : {', '.join(active_sets) if active_sets else 'None'}",
        f" Raw Entropy       : {result.raw_entropy} bits",
        f" Effective Entropy : {result.effective_entropy} bits",
        f" Strength Rating   : {result.rating_colored}",
        "-" * 65,
        " ⏱️  ESTIMATED BRUTE-FORCE TIME:",
        f"   • Online Throttled (100/s)   : {result.crack_estimates.online_attack}",
        f"   • Fast Single GPU (1B/s)     : {result.crack_estimates.offline_gpu}",
        f"   • GPU Cluster Rig (1T/s)     : {result.crack_estimates.supercomputer_cluster}",
        "-" * 65,
        " 🔍 PATTERN & VULNERABILITY ANALYSIS:"
    ]

    if not result.findings:
        lines.append("   ✓ No obvious patterns or dictionary words detected.")
    else:
        for f in result.findings:
            if f.severity == Severity.CRITICAL:
                icon = "❌"
            elif f.severity == Severity.WARNING:
                icon = "⚠️ "
            elif f.severity == Severity.GOOD:
                icon = "✅"
            else:
                icon = "ℹ️ "
            lines.append(f"   {icon} [{f.severity.value}] {f.message}")

    if result.recommendations:
        lines.append("-" * 65)
        lines.append(" 💡 RECOMMENDATIONS:")
        for rec in result.recommendations:
            lines.append(f"   👉 {rec}")

    lines.append("=" * 65)
    lines.append("")
    return "\n".join(lines)


def format_batch_table(results: List[Tuple[str, AnalysisResult]]) -> str:
    """Formats a batch analysis table for terminal display."""
    lines = [
        f"\nBatch analysis of {len(results)} passwords:\n",
        f"{'#':<4} {'Masked Password':<22} {'Length':<8} {'Entropy':<10} {'Rating':<15} {'Crack Time (GPU)'}",
        "-" * 88
    ]

    for idx, (raw_pwd, res) in enumerate(results, start=1):
        masked = raw_pwd[0] + "*" * (len(raw_pwd) - 1) if len(raw_pwd) > 1 else "*"
        if len(masked) > 20:
            masked = masked[:17] + "..."

        gpu_time = res.crack_estimates.offline_gpu if res.crack_estimates else "N/A"
        rating_str = f"{res.rating_colored:<24}"
        lines.append(f"{idx:<4} {masked:<22} {res.length:<8} {res.effective_entropy:<10.1f} {rating_str} {gpu_time}")

    lines.append("\nBatch analysis complete.\n")
    return "\n".join(lines)


def result_to_dict(password: str, result: AnalysisResult, include_cleartext: bool = False) -> Dict[str, Any]:
    """Converts AnalysisResult to a serializable dictionary."""
    data = {
        "password_masked": result.password_masked,
        "length": result.length,
        "pool_size": result.pool_size,
        "charset_flags": result.charset_flags,
        "raw_entropy_bits": result.raw_entropy,
        "effective_entropy_bits": result.effective_entropy,
        "rating": result.rating.value,
        "crack_estimates": {
            "online_throttled": result.crack_estimates.online_attack,
            "fast_gpu": result.crack_estimates.offline_gpu,
            "gpu_cluster": result.crack_estimates.supercomputer_cluster
        } if result.crack_estimates else {},
        "findings": [{"severity": f.severity.value, "message": f.message} for f in result.findings],
        "recommendations": result.recommendations
    }
    if include_cleartext:
        data["password"] = password
    return data
