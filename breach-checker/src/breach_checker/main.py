"""Command line and interactive interface for Breach Checker."""

import argparse
import os
import sys
from typing import List, Optional

from breach_checker.client import get_client
from breach_checker.models import CheckResult, ScanSummary, Status
from breach_checker.scanner import export_results, load_targets_from_file, scan_targets

# Terminal styling constants
USE_COLOR = sys.stdout.isatty() and os.getenv("NO_COLOR") is None

def _c(text: str, color_code: str) -> str:
    return f"\033[{color_code}m{text}\033[0m" if USE_COLOR else text

def red(t: str) -> str: return _c(t, "1;31")
def green(t: str) -> str: return _c(t, "1;32")
def yellow(t: str) -> str: return _c(t, "1;33")
def cyan(t: str) -> str: return _c(t, "1;36")
def bold(t: str) -> str: return _c(t, "1")
def dim(t: str) -> str: return _c(t, "2")


BANNER = r"""
  ____                      _        ____ _               _             
 | __ ) _ __ ___  __ _  ___| |__    / ___| |__   ___  ___| | _____ _ __ 
 |  _ \| '__/ _ \/ _` |/ __| '_ \  | |   | '_ \ / _ \/ __| |/ / _ \ '__|
 | |_) | | |  __/ (_| | (__| | | | | |___| | | |  __/ (__|   <  __/ |   
 |____/|_|  \___|\__,_|\___|_| |_|  \____|_| |_|\___|\___|_|\_\___|_|   
"""


def print_banner() -> None:
    print(cyan(BANNER))
    print(dim("  Day 3 - 30 Days of Python Challenge | Public Breach Search Tool"))
    print(dim("=" * 72))


def print_single_result(result: CheckResult, verbose: bool = False) -> None:
    """Pretty-print result for a single checked account."""
    if result.status == Status.BREACHED:
        print(f"\n{red('[!] BREACH DETECTED')} for {bold(result.account)}")
        print(f"    Total Breaches Found: {red(str(result.breach_count))}")
        print(f"    Provider            : {result.provider}")
        print(f"    Lookup Time         : {result.response_time:.3f}s\n")

        print("    " + dim("-" * 64))
        for b in result.breaches:
            title = b.title or b.name
            date_info = f" [{b.breach_date}]" if b.breach_date else ""
            domain_info = f" ({b.domain})" if b.domain else ""
            print(f"    • {bold(title)}{date_info}{domain_info}")

            if b.pwn_count:
                print(f"      Impacted Accounts : {b.pwn_count:,}")
            if b.data_classes:
                print(f"      Compromised Data  : {yellow(', '.join(b.data_classes))}")
            if verbose and b.description:
                # Strip simple HTML tags if present in description
                desc = b.description.replace("&quot;", '"').replace("&amp;", "&")
                clean_desc = "".join(c for i, c in enumerate(desc) if not (c == "<" or desc[max(0, i-10):i].count("<") > desc[max(0, i-10):i].count(">")))
                print(f"      Details           : {clean_desc[:200]}...")
        print("    " + dim("-" * 64))

    elif result.status == Status.CLEAN:
        print(f"\n{green('[+] ALL CLEAN')} : {bold(result.account)}")
        print(f"    No breach exposures identified on {result.provider}.")
        print(f"    Lookup Time: {result.response_time:.3f}s")

    else:
        print(f"\n{yellow('[-] ERROR')} for {bold(result.account)}")
        print(f"    Provider : {result.provider}")
        print(f"    Message  : {result.error_message}")


def print_batch_summary(summary: ScanSummary) -> None:
    """Print overall summary statistics for a batch scan."""
    print("\n" + cyan("=" * 72))
    print(bold("BATCH SCAN SUMMARY"))
    print(cyan("=" * 72))
    print(f"[*] Total Accounts Queried : {summary.total}")
    print(f"[*] {red('Breached Accounts')}      : {summary.breached}")
    print(f"[*] {green('Clean Accounts')}         : {summary.clean}")
    print(f"[*] {yellow('Errors / Skipped')}       : {summary.errors}")
    print(f"[*] Total Duration         : {summary.duration_seconds:.2f}s")
    print(cyan("=" * 72))


def run_interactive(client_provider: str = "auto", api_key: Optional[str] = None) -> None:
    """Interactive CLI menu for user-friendly execution."""
    print_banner()
    client = get_client(client_provider, api_key)
    print(f"Active Provider: {bold(client.name.upper())}")
    if client.name == "xposedornot":
        print(dim("  -> Free public tier (No API key required). Supports email checks."))
    else:
        print(dim("  -> Have I Been Pwned API v3. Supports emails & usernames."))
    print()

    while True:
        print(bold("Choose an option:"))
        print("  1. Check a single email / username")
        print("  2. Batch check accounts from a text or CSV file")
        print("  3. Exit")

        try:
            choice = input(cyan("\nEnter selection [1-3]: ")).strip()
        except (KeyboardInterrupt, EOFError):
            print("\nGoodbye!")
            break

        if choice == "1":
            try:
                target = input("\nEnter email or username to check: ").strip()
            except (KeyboardInterrupt, EOFError):
                break
            if not target:
                print(yellow("No target entered. Returning to menu."))
                continue

            print(dim(f"[*] Querying {client.name}..."))
            result = client.check(target)
            print_single_result(result, verbose=True)

            # Option to export single check
            save = input("\nSave result to file? (y/N): ").strip().lower()
            if save == "y":
                out_path = input("Enter output filename (e.g. result.json, result.txt): ").strip()
                if out_path:
                    summary = ScanSummary(duration_seconds=result.response_time)
                    summary.add_result(result)
                    fmt = export_results(summary, out_path)
                    print(green(f"[+] Saved {fmt.upper()} report to {out_path}"))
            print()

        elif choice == "2":
            try:
                file_path = input("\nEnter path to target file (.txt or .csv): ").strip()
            except (KeyboardInterrupt, EOFError):
                break
            if not file_path:
                print(yellow("No file path entered. Returning to menu."))
                continue

            try:
                targets = load_targets_from_file(file_path)
            except Exception as e:
                print(red(f"[!] Error reading file: {e}"))
                continue

            print(dim(f"[*] Loaded {len(targets)} unique targets from {file_path}."))

            delay_str = input("Delay between queries in seconds [default 1.5]: ").strip()
            delay = float(delay_str) if delay_str else 1.5

            def on_progress(curr: int, total: int, target: str, res: CheckResult):
                status_tag = red("BREACHED") if res.status == Status.BREACHED else (
                    green("CLEAN") if res.status == Status.CLEAN else yellow("ERROR")
                )
                extra = f"({res.breach_count} breaches)" if res.status == Status.BREACHED else ""
                print(f"[{curr}/{total}] {target:35} -> {status_tag} {extra}")

            print(dim("\n[*] Starting scan...\n"))
            summary = scan_targets(targets, client, delay_seconds=delay, on_progress=on_progress)
            print_batch_summary(summary)

            save = input("\nSave results to file? (y/N): ").strip().lower()
            if save == "y":
                out_path = input("Enter output filename (e.g. results.csv, results.json, results.txt): ").strip()
                if out_path:
                    fmt = export_results(summary, out_path)
                    print(green(f"[+] Successfully exported {fmt.upper()} report to {out_path}"))
            print()

        elif choice == "3":
            print("Exiting. Stay secure!")
            break
        else:
            print(yellow("Invalid choice, please select 1, 2, or 3."))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="breach-checker",
        description="Public API email and username data breach checker (Day 3 - 30 Days of Python Challenge).",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-t", "--target",
        type=str,
        help="Single email address or username to check",
    )
    group.add_argument(
        "-f", "--file",
        type=str,
        help="Path to file containing list of emails/usernames (.txt or .csv)",
    )
    parser.add_argument(
        "-p", "--provider",
        type=str,
        choices=["auto", "xposedornot", "hibp"],
        default="auto",
        help="Breach API provider (default: auto; uses HIBP if key available, else XposedOrNot free API)",
    )
    parser.add_argument(
        "-k", "--api-key",
        type=str,
        default=None,
        help="Have I Been Pwned API key (or set HIBP_API_KEY environment variable)",
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Output file path to save results (.json, .csv, or .txt)",
    )
    parser.add_argument(
        "--format",
        type=str,
        choices=["json", "csv", "txt"],
        default=None,
        help="Explicitly choose export format if different from file extension",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=1.5,
        help="Seconds to wait between batch queries to respect API rate limits (default: 1.5)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Display detailed descriptions and metadata for breached accounts",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # If no flags passed, launch interactive mode
    if not args.target and not args.file:
        run_interactive(client_provider=args.provider, api_key=args.api_key)
        return

    print_banner()

    try:
        client = get_client(provider=args.provider, api_key=args.api_key)
    except ValueError as e:
        print(red(f"[!] Error: {e}"))
        sys.exit(1)

    print(f"[*] API Provider: {bold(client.name.upper())}")

    # Single target check
    if args.target:
        print(dim(f"[*] Checking breach records for: {args.target}..."))
        result = client.check(args.target)
        print_single_result(result, verbose=args.verbose)

        if args.output:
            summary = ScanSummary(duration_seconds=result.response_time)
            summary.add_result(result)
            fmt = export_results(summary, args.output, format_type=args.format)
            print(green(f"\n[+] Saved scan result to '{args.output}' ({fmt.upper()})"))

    # Batch target file check
    elif args.file:
        try:
            targets = load_targets_from_file(args.file)
        except Exception as e:
            print(red(f"[!] Failed to read target file: {e}"))
            sys.exit(1)

        print(f"[*] Loaded {len(targets)} targets from {args.file}")
        print(f"[*] Query delay: {args.delay}s per request\n")

        def on_progress(curr: int, total: int, target: str, res: CheckResult):
            status_tag = red("BREACHED") if res.status == Status.BREACHED else (
                green("CLEAN") if res.status == Status.CLEAN else yellow("ERROR")
            )
            extra = f"({res.breach_count} breaches)" if res.status == Status.BREACHED else ""
            print(f"[{curr}/{total}] {target:35} -> {status_tag} {extra}")

        summary = scan_targets(targets, client, delay_seconds=args.delay, on_progress=on_progress)
        print_batch_summary(summary)

        if args.output:
            fmt = export_results(summary, args.output, format_type=args.format)
            print(green(f"\n[+] Saved batch scan results to '{args.output}' ({fmt.upper()})"))


if __name__ == "__main__":
    main()

