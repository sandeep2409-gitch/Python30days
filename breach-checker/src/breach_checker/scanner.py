"""Scanner logic for single and batch breach lookups, file parsing, and result export."""

import csv
import json
import os
import time
from typing import Callable, List, Optional

from breach_checker.client import BaseBreachClient
from breach_checker.models import CheckResult, ScanSummary, Status


def load_targets_from_file(file_path: str) -> List[str]:
    """Load and normalize emails/usernames from a text or CSV file.
    
    Ignores blank lines and comments starting with '#'.
    Preserves order while removing duplicate entries.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Target file not found: {file_path}")

    targets: List[str] = []
    seen = set()

    is_csv = file_path.lower().endswith(".csv")

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        if is_csv:
            reader = csv.reader(f)
            header = None
            col_idx = 0
            for row in reader:
                if not row:
                    continue
                # If header row, check for column name
                if header is None:
                    lowered = [c.strip().lower() for c in row]
                    for candidate in ["email", "username", "account", "target"]:
                        if candidate in lowered:
                            col_idx = lowered.index(candidate)
                            header = row
                            break
                    if header is not None:
                        continue  # skip header row
                    header = row  # no named header found, treat as first data row

                if len(row) > col_idx:
                    val = row[col_idx].strip()
                    if val and val not in seen and not val.startswith("#"):
                        seen.add(val)
                        targets.append(val)
        else:
            for line in f:
                val = line.strip()
                if val and not val.startswith("#") and val not in seen:
                    seen.add(val)
                    targets.append(val)

    return targets


def scan_targets(
    targets: List[str],
    client: BaseBreachClient,
    delay_seconds: float = 1.5,
    on_progress: Optional[Callable[[int, int, str, CheckResult], None]] = None,
) -> ScanSummary:
    """Scan a list of targets against the breach client with polite rate pacing."""
    summary = ScanSummary()
    total = len(targets)
    start_time = time.time()

    for idx, target in enumerate(targets, start=1):
        result = client.check(target)
        summary.add_result(result)

        if on_progress:
            on_progress(idx, total, target, result)

        # Pace requests between queries (skip delay after last query)
        if idx < total and delay_seconds > 0:
            time.sleep(delay_seconds)

    summary.duration_seconds = time.time() - start_time
    return summary


def export_to_json(summary: ScanSummary, output_path: str) -> None:
    """Save scan results to a formatted JSON file."""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(summary.to_dict(), f, indent=2)


def export_to_csv(summary: ScanSummary, output_path: str) -> None:
    """Save scan results to a CSV file."""
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Account", "Provider", "Status", "BreachCount", "BreachNames", "ErrorMessage", "ResponseTimeSeconds"])
        for r in summary.results:
            breach_names = "; ".join(b.name for b in r.breaches)
            writer.writerow([
                r.account,
                r.provider,
                r.status.value,
                r.breach_count,
                breach_names,
                r.error_message or "",
                round(r.response_time, 3),
            ])


def export_to_text(summary: ScanSummary, output_path: str) -> None:
    """Save human-readable scan report to a text file."""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("=======================================================\n")
        f.write("             BREACH CHECKER SCAN REPORT                \n")
        f.write("=======================================================\n")
        f.write(f"Total Queried : {summary.total}\n")
        f.write(f"Breached      : {summary.breached}\n")
        f.write(f"Clean         : {summary.clean}\n")
        f.write(f"Errors        : {summary.errors}\n")
        f.write(f"Duration      : {summary.duration_seconds:.2f}s\n")
        f.write("=======================================================\n\n")

        for r in summary.results:
            if r.status == Status.BREACHED:
                f.write(f"[!] BREACHED: {r.account} ({r.breach_count} exposures)\n")
                for b in r.breaches:
                    meta = []
                    if b.breach_date:
                        meta.append(f"Date: {b.breach_date}")
                    if b.domain:
                        meta.append(f"Domain: {b.domain}")
                    if b.pwn_count:
                        meta.append(f"Accounts: {b.pwn_count:,}")
                    meta_str = f" ({', '.join(meta)})" if meta else ""
                    f.write(f"    - {b.name}{meta_str}\n")
                    if b.data_classes:
                        f.write(f"      Exposed: {', '.join(b.data_classes)}\n")
            elif r.status == Status.CLEAN:
                f.write(f"[+] CLEAN   : {r.account} (No breaches found)\n")
            else:
                f.write(f"[-] ERROR   : {r.account} ({r.error_message})\n")
            f.write("\n")


def export_results(summary: ScanSummary, output_path: str, format_type: Optional[str] = None) -> str:
    """Export results to file based on extension or explicit format ('json', 'csv', 'txt')."""
    fmt = (format_type or "").lower()
    if not fmt:
        if output_path.endswith(".json"):
            fmt = "json"
        elif output_path.endswith(".csv"):
            fmt = "csv"
        else:
            fmt = "txt"

    if fmt == "json":
        export_to_json(summary, output_path)
    elif fmt == "csv":
        export_to_csv(summary, output_path)
    else:
        export_to_text(summary, output_path)

    return fmt

