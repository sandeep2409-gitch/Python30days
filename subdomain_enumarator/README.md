# Day 2: Wordlist-Based Subdomain Enumerator

A fast, multi-threaded subdomain discovery tool written in Python as part of the **#30DaysOfPython** challenge.

## Features

- **Wordlist-based Brute Force**: Tests common subdomain prefixes (`www`, `mail`, `dev`, `api`, `staging`, etc.).
- **DNS Resolution**: Resolves candidate hostnames to active IP addresses using `socket.gethostbyname`.
- **Concurrent & Fast**: Uses `concurrent.futures.ThreadPoolExecutor` for multi-threaded lookups.
- **Dual Mode**:
  - **CLI Mode**: Run with flags (`-d`, `-w`, `-t`, `-o`) for automation and scripting.
  - **Interactive Mode**: Prompts for inputs if no command-line arguments are provided.
- **Output Export**: Optionally saves active subdomains and resolved IPs directly to a text file.
- **Zero Heavy Dependencies**: Built with Python standard library modules.

---

## Installation & Setup

```bash
cd subdomain_enumarator

# Create and activate virtual environment (using uv or python -m venv)
uv venv
source .venv/bin/activate

# Install the project
uv pip install -e .
```

---

## Usage

### 1. Interactive Mode
Run without arguments to be prompted interactively:
```bash
subdomain-enumarator
# or
python -m subdomain_enumarator
```

### 2. Command Line Arguments
```bash
# Basic scan with default wordlist
subdomain-enumarator -d example.com

# Scan with custom wordlist, 20 threads, and output to a file
subdomain-enumarator -d example.com -w wordlist.txt -t 20 -o live_subs.txt
```

### CLI Options:
| Flag | Description | Default |
|------|-------------|---------|
| `-d, --domain` | Target domain to enumerate (e.g. `example.com`) | Interactive prompt |
| `-w, --wordlist` | Path to custom wordlist text file | `wordlist.txt` / built-in list |
| `-t, --threads` | Number of concurrent worker threads | `10` |
| `-o, --output` | File path to save resolved subdomains | None |

---

## Sample Output

```text
=======================================================
[*] Target Domain   : example.com
[*] Wordlist Size   : 90 entries
[*] Threads         : 10
[*] Output File     : results.txt
=======================================================

[*] Starting enumeration...

[+] Discovered: www.example.com                     -> 93.184.216.34
[+] Discovered: mail.example.com                    -> 93.184.216.35
[+] Discovered: api.example.com                     -> 93.184.216.36

-------------------------------------------------------
[*] Scan finished in 0.85 seconds.
[*] Total subdomains discovered: 3 / 90
-------------------------------------------------------

[+] Saved 3 results to 'results.txt'
```

---

## Running Unit Tests

```bash
python -m unittest discover -s tests
```

