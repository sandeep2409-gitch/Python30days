# Day 3: Email & Username Breach Checker

A fast, flexible, and zero-dependency security tool to check email addresses and usernames against known data breaches, built as part of the **#30DaysOfPython** challenge.

---

## Features

- **Public & Free API by Default**: Uses **XposedOrNot** for free out-of-the-box email breach lookups with **no API key required**.
- **Have I Been Pwned (HIBP v3) Support**: Seamlessly switch to HIBP by providing an API key via CLI flag (`-k/--api-key`) or environment variable (`HIBP_API_KEY`) to check both usernames and emails.
- **Dual Execution Mode**:
  - **Interactive Mode**: Launch without arguments for a guided, interactive terminal menu.
  - **CLI Mode**: Run with flags (`-t`, `-f`, `-o`, `-p`, `--delay`) for automation, scripting, and pipeline integration.
- **Batch Scanning**: Check multiple targets from `.txt` files (one per line, `#` comments ignored) or `.csv` spreadsheets.
- **Polite Rate Pacing**: Configurable delay between batch requests (default: 1.5s) to stay respectful of public API rate limits.
- **Multi-Format Export**: Save findings to `.json`, `.csv`, or formatted `.txt` reports (`-o / --output`).
- **Zero External Dependencies**: Engineered entirely with Python's standard library (`urllib.request`, `json`, `csv`, `argparse`, `dataclasses`).

---

## Installation & Setup

```bash
cd breach-checker

# Create and activate virtual environment (using uv or python -m venv)
uv venv
source .venv/bin/activate

# Install in editable mode
uv pip install -e .
```

Alternatively, you can run it directly without installation:
```bash
python3 -m breach_checker --help
```

---

## Usage

### 1. Interactive Mode
Run without arguments to launch the interactive menu:
```bash
breach-checker
# or
python3 -m breach_checker
```

```text
  ____                      _        ____ _               _             
 | __ ) _ __ ___  __ _  ___| |__    / ___| |__   ___  ___| | _____ _ __ 
 |  _ \| '__/ _ \/ _` |/ __| '_ \  | |   | '_ \ / _ \/ __| |/ / _ \ '__|
 | |_) | | |  __/ (_| | (__| | | | | |___| | | |  __/ (__|   <  __/ |   
 |____/|_|  \___|\__,_|\___|_| |_|  \____|_| |_|\___|\___|_|\_\___|_|   

  Day 3 - 30 Days of Python Challenge | Public Breach Search Tool
========================================================================
Active Provider: XPOSEDORNOT
  -> Free public tier (No API key required). Supports email checks.

Choose an option:
  1. Check a single email / username
  2. Batch check accounts from a text or CSV file
  3. Exit

Enter selection [1-3]: 1
```

---

### 2. Command Line Mode

#### Check a Single Email (Free Public API)
```bash
breach-checker -t victim@example.com
```

#### Verbose Output (Detailed breach description & compromised data classes)
```bash
breach-checker -t victim@example.com -v
```

#### Batch Check Targets from a File with JSON Export
```bash
breach-checker -f sample_targets.txt -o results.json
```

#### Batch Check with CSV Export & Custom Pacing
```bash
breach-checker -f targets.csv -o results.csv --delay 2.0
```

#### Using Have I Been Pwned (HIBP v3)
```bash
# Via CLI flag
breach-checker -t username123 -p hibp -k "YOUR_HIBP_API_KEY"

# Or via environment variable
export HIBP_API_KEY="YOUR_HIBP_API_KEY"
breach-checker -t username123
```

---

## CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | Single email address or username to check | None (launches interactive mode) |
| `-f, --file` | Path to text (`.txt`) or CSV (`.csv`) target file | None |
| `-p, --provider` | Provider: `auto`, `xposedornot`, or `hibp` | `auto` |
| `-k, --api-key` | Have I Been Pwned API key | `$HIBP_API_KEY` |
| `-o, --output` | Output file path (`.json`, `.csv`, `.txt`) | None |
| `--format` | Force export format (`json`, `csv`, `txt`) | Inferred from file extension |
| `--delay` | Delay in seconds between batch queries | `1.5` |
| `-v, --verbose` | Show detailed breach descriptions | `False` |

---

## Sample Output

### Single Target Breach Alert
```text
[!] BREACH DETECTED for victim@example.com
    Total Breaches Found: 3
    Provider            : xposedornot
    Lookup Time         : 0.412s

    ----------------------------------------------------------------
    • Adobe Systems [2013-10-04] (adobe.com)
      Impacted Accounts : 152,445,165
      Compromised Data  : Email addresses, Password hints, Passwords, Usernames
    • LinkedIn [2012-06-05] (linkedin.com)
      Impacted Accounts : 164,611,595
      Compromised Data  : Email addresses, Passwords
    • Canva [2019-05-24] (canva.com)
      Impacted Accounts : 137,272,308
      Compromised Data  : Email addresses, Geographic locations, Names, Passwords
    ----------------------------------------------------------------
```

### Batch Scan Summary
```text
[*] API Provider: XPOSEDORNOT
[*] Loaded 5 targets from targets.txt
[*] Query delay: 1.5s per request

[1/5] employee1@company.com              -> CLEAN 
[2/5] test@example.com                   -> BREACHED (3 breaches)
[3/5] admin@gmail.com                    -> BREACHED (12 breaches)
[4/5] secure_dev@internal.io             -> CLEAN 
[5/5] support@service.org                -> CLEAN 

========================================================================
BATCH SCAN SUMMARY
========================================================================
[*] Total Accounts Queried : 5
[*] Breached Accounts      : 2
[*] Clean Accounts         : 3
[*] Errors / Skipped       : 0
[*] Total Duration         : 6.45s
========================================================================

[+] Saved batch scan results to 'results.csv' (CSV)
```

---

## Running Unit Tests

Run the test suite with standard `unittest`:

```bash
python3 -m unittest discover -s tests -v
```

All 20 unit tests execute with mocked HTTP responses and require zero network access.

