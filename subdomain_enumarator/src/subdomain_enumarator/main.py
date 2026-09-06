import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import socket
import sys
import threading
import time

# Top 50 common subdomains used as default fallback if no wordlist is supplied
DEFAULT_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test",
    "portal", "ns", "ww1", "host", "support", "dev", "dev2", "api",
    "beta", "admin", "staging", "app", "auth", "status", "cdn", "docs",
    "git", "internal", "monitoring", "dashboard", "login", "stage",
    "assets", "mobile", "static", "media", "email", "cloud", "db",
    "direct", "gateway", "backend", "billing", "demo"
]

# Mutex to ensure console output doesn't interleave across threads
print_lock = threading.Lock()


def clean_domain(raw_domain: str) -> str:
    """
    Sanitize the input domain string by removing protocols, leading @,
    trailing slashes, and whitespace.
    """
    domain = raw_domain.strip()
    if domain.startswith("@"):
        domain = domain[1:]
    if domain.startswith("http://"):
        domain = domain[7:]
    elif domain.startswith("https://"):
        domain = domain[8:]
    domain = domain.split("/")[0]  # Remove path components if any
    domain = domain.split(":")[0]  # Remove port if specified
    return domain.strip()


def check_subdomain(domain: str, subdomain: str) -> tuple[str, str | None]:
    """
    Attempts to resolve <subdomain>.<domain> using standard DNS lookup.
    Returns a tuple of (fqdn, ip_address) if resolved, or (fqdn, None) if not.
    """
    fqdn = f"{subdomain.strip()}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return fqdn, ip
    except (socket.gaierror, socket.herror, socket.timeout, OSError):
        return fqdn, None


def load_wordlist(filepath: str | None = None) -> list[str]:
    """
    Loads subdomains from a wordlist file. If no file is provided or the file
    doesn't exist, falls back to the default list.
    """
    if not filepath:
        # Check if local wordlist.txt exists in working directory or package directory
        local_candidate = Path("wordlist.txt")
        if local_candidate.exists():
            with open(local_candidate, "r", encoding="utf-8") as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]
        return DEFAULT_SUBDOMAINS

    path = Path(filepath)
    if not path.is_file():
        print(f"[!] Warning: Wordlist file '{filepath}' not found. Using default list.")
        return DEFAULT_SUBDOMAINS

    with open(path, "r", encoding="utf-8") as f:
        words = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    return words if words else DEFAULT_SUBDOMAINS


def enumerate_subdomains(
    domain: str,
    wordlist: list[str],
    threads: int = 10,
    output_file: str | None = None,
) -> list[tuple[str, str]]:
    """
    Concurrently resolves subdomains using ThreadPoolExecutor.
    Prints discoveries in real-time and optionally writes them to output_file.
    """
    print(f"\n{'='*55}")
    print(f"[*] Target Domain   : {domain}")
    print(f"[*] Wordlist Size   : {len(wordlist)} entries")
    print(f"[*] Threads         : {threads}")
    if output_file:
        print(f"[*] Output File     : {output_file}")
    print(f"{'='*55}\n")
    print("[*] Starting enumeration...\n")

    start_time = time.time()
    discovered: list[tuple[str, str]] = []

    try:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            # Submit resolution tasks
            future_to_sub = {
                executor.submit(check_subdomain, domain, sub): sub
                for sub in wordlist
            }

            for future in as_completed(future_to_sub):
                fqdn, ip = future.result()
                if ip:
                    with print_lock:
                        print(f"[+] Discovered: {fqdn:<35} -> {ip}")
                        discovered.append((fqdn, ip))

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")

    elapsed = time.time() - start_time
    print(f"\n{'-'*55}")
    print(f"[*] Scan finished in {elapsed:.2f} seconds.")
    print(f"[*] Total subdomains discovered: {len(discovered)} / {len(wordlist)}")
    print(f"{'-'*55}\n")

    if output_file and discovered:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(f"# Subdomain Enumeration Results for {domain}\n")
                f.write(f"# Generated on {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                for fqdn, ip in sorted(discovered):
                    f.write(f"{fqdn} -> {ip}\n")
            print(f"[+] Saved {len(discovered)} results to '{output_file}'")
        except OSError as e:
            print(f"[!] Failed to write to output file: {e}")

    return discovered


def parse_arguments() -> argparse.Namespace:
    """Parses command line arguments."""
    parser = argparse.ArgumentParser(
        description="Day 2: Fast Wordlist-Based Subdomain Enumerator (Multi-threaded)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-d", "--domain",
        help="Target domain to enumerate (e.g., example.com)",
    )
    parser.add_argument(
        "-w", "--wordlist",
        help="Path to custom wordlist file (defaults to wordlist.txt or built-in list)",
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        help="Number of concurrent worker threads",
    )
    parser.add_argument(
        "-o", "--output",
        help="Optional file path to save live subdomains",
    )
    return parser.parse_args()


def interactive_prompt() -> tuple[str, str | None, int, str | None]:
    """Provides an interactive CLI prompt if arguments are omitted."""
    print("=" * 55)
    print("   Subdomain Enumerator (Python 30 Days - Day 2)")
    print("=" * 55)

    raw_domain = input("Enter target domain (e.g., example.com): ").strip()
    while not raw_domain:
        print("[!] Domain cannot be empty.")
        raw_domain = input("Enter target domain: ").strip()

    wordlist_input = input("Enter wordlist path (press Enter for default): ").strip()
    wordlist_path = wordlist_input if wordlist_input else None

    threads_input = input("Enter number of threads [default: 10]: ").strip()
    try:
        threads = int(threads_input) if threads_input else 10
    except ValueError:
        print("[!] Invalid thread count, defaulting to 10.")
        threads = 10

    output_input = input("Save results to file? (filename or press Enter to skip): ").strip()
    output_file = output_input if output_input else None

    return raw_domain, wordlist_path, threads, output_file


def main() -> None:
    args = parse_arguments()

    if args.domain:
        domain = clean_domain(args.domain)
        wordlist_path = args.wordlist
        threads = args.threads
        output_file = args.output
    else:
        # Fallback to interactive mode if no domain is provided via CLI
        domain_raw, wordlist_path, threads, output_file = interactive_prompt()
        domain = clean_domain(domain_raw)

    wordlist = load_wordlist(wordlist_path)
    enumerate_subdomains(
        domain=domain,
        wordlist=wordlist,
        threads=threads,
        output_file=output_file,
    )


if __name__ == "__main__":
    main()

