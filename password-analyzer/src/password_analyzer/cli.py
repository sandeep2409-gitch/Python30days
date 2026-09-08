"""
CLI interface for Password Strength Analyzer & Shannon Entropy Calculator.
"""

import argparse
import getpass
import json
from pathlib import Path
import sys
from typing import List, Tuple
from .analyzer import PasswordAnalyzer
from .formatter import format_batch_table, format_single_report, result_to_dict
from .models import AnalysisResult


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="password-analyzer",
        description="Day 4: Password Strength Analyzer & Shannon Entropy Calculator"
    )
    parser.add_argument(
        "-p", "--password",
        type=str,
        help="Target password to analyze (warning: visible in shell history)."
    )
    parser.add_argument(
        "-f", "--file",
        type=str,
        help="Batch mode: Path to text file containing passwords (one per line)."
    )
    parser.add_argument(
        "--leak-db",
        type=str,
        help="Optional path to custom breached password wordlist (e.g. rockyou.txt)."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output structured JSON instead of human-readable report."
    )
    parser.add_argument(
        "--show-clear",
        action="store_true",
        help="Show cleartext password in the terminal report (masked by default)."
    )
    return parser.parse_args()


def run_cli() -> None:
    args = parse_arguments()
    analyzer = PasswordAnalyzer(external_leak_file=args.leak_db)

    # 1. Direct password provided via argument
    if args.password:
        result = analyzer.analyze(args.password)
        if args.json:
            print(json.dumps(result_to_dict(args.password, result, include_cleartext=args.show_clear), indent=2))
        else:
            print(format_single_report(args.password, result, show_cleartext=args.show_clear))
        return

    # 2. Batch mode from file
    if args.file:
        file_path = Path(args.file)
        if not file_path.is_file():
            print(f"Error: File '{args.file}' not found.", file=sys.stderr)
            sys.exit(1)

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            passwords = [line.strip() for line in f if line.strip()]

        batch_results: List[Tuple[str, AnalysisResult]] = [
            (pwd, analyzer.analyze(pwd)) for pwd in passwords
        ]

        if args.json:
            json_list = [
                result_to_dict(pwd, res, include_cleartext=args.show_clear)
                for pwd, res in batch_results
            ]
            print(json.dumps(json_list, indent=2))
        else:
            print(format_batch_table(batch_results))
        return

    # 3. Piped stdin input (e.g. cat list.txt | password-analyzer)
    if not sys.stdin.isatty():
        piped_passwords = [line.strip() for line in sys.stdin if line.strip()]
        if piped_passwords:
            batch_results = [
                (pwd, analyzer.analyze(pwd)) for pwd in piped_passwords
            ]
            if args.json:
                json_list = [
                    result_to_dict(pwd, res, include_cleartext=args.show_clear)
                    for pwd, res in batch_results
                ]
                print(json.dumps(json_list, indent=2))
            else:
                print(format_batch_table(batch_results))
            return

    # 4. Interactive secure mode
    print("🔐 Password Strength Analyzer (Interactive Mode)")
    target = getpass.getpass("Enter password to analyze (input hidden): ")
    if not target:
        print("No password entered. Exiting.")
        sys.exit(0)

    result = analyzer.analyze(target)
    if args.json:
        print(json.dumps(result_to_dict(target, result, include_cleartext=args.show_clear), indent=2))
    else:
        print(format_single_report(target, result, show_cleartext=args.show_clear))
