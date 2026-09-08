# 🔐 Password Strength Analyzer & Shannon Entropy Calculator

[![Python](https://img.shields.io/badge/Python-3.13%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20external-brightgreen.svg)]()
[![Challenge](https://img.shields.io/badge/Challenge-30DaysOfPython%20Day%204-orange.svg)]()

A robust security CLI tool built for **Day 4 of the #30DaysOfPython challenge**. It analyzes password strength using **Shannon information entropy**, detects common human vulnerabilities (keyboard walks, dictionary words, and l33tspeak substitutions), and checks against known breach datasets (RockYou-style).

---

## 🌟 Key Features

- 🧮 **Shannon Entropy Engine**: Calculates theoretical bits ($L \times \log_2(R)$) based on character pool size.
- 📉 **Effective Entropy Score**: Applies structural degradation penalties for predictable patterns, yielding an accurate real-world resistance metric.
- 🔡 **L33tspeak De-obfuscation**: Decodes common character swaps (`@` $\rightarrow$ `a`, `0` $\rightarrow$ `o`, `$` $\rightarrow$ `s`) to unmask hidden dictionary words.
- ⌨️ **Pattern & Walk Detection**: Detects sequential runs (`12345`, `abcdef`) and keyboard walks (`qwerty`, `asdfgh`).
- 🚨 **Breached Passwords Checker**: Compares targets in $O(1)$ time against curated top breach databases or custom wordlists.
- ⏱️ **Multi-Tier Crack Estimator**: Estimates brute-force durations against online throttled systems, modern GPUs, and high-performance cracking clusters.
- 📁 **Batch Processing & Pipelines**: Analyzes lists from `.txt` files or piped `stdin` with formatted tables or JSON export.
- ⚡ **Zero Dependencies**: Pure Python standard library (`math`, `re`, `argparse`, `getpass`, `dataclasses`, `json`).

---

## 🚀 Quickstart

### Prerequisites
- Python 3.13+ (or Python 3.8+)
- (Optional) [uv](https://github.com/astral-sh/uv)

### 1. Interactive Mode (Input Hidden)
```bash
python3 -m password_analyzer
```
*(Prompts for password securely without echoing characters to the terminal)*

### 2. Direct Password Analysis
```bash
python3 -m password_analyzer -p "P@ssw0rd123!" --show-clear
```

### 3. Batch Analysis from File
```bash
python3 -m password_analyzer -f sample_passwords.txt
```

### 4. Piped Input via Stdin
```bash
cat sample_passwords.txt | python3 -m password_analyzer
```

### 5. JSON Output (for CI/CD Pipelines or Audits)
```bash
python3 -m password_analyzer -p "Secret!99" --json
```

### 6. Using Custom Leak Lists (e.g. `rockyou.txt`)
```bash
python3 -m password_analyzer -p "mycustompass" --leak-db path/to/rockyou.txt
```

---

## 🧮 The Mathematics of Password Entropy

Shannon Entropy measures the amount of uncertainty or information content in bits:

$$H = L \times \log_2(R)$$

Where:
- $L$ = Length of password.
- $R$ = Pool size (number of possible characters per position):
  - Lowercase letters: $26$
  - Uppercase letters: $26$
  - Digits: $10$
  - Standard ASCII symbols: $32$
  - Whitespace: $1$

### Theoretical vs. Effective Entropy
A password like `P@ssw0rd123!` has $L=12$ and $R=94$, giving **78.6 bits** of theoretical entropy. However:
- Attackers do not brute-force randomly; they apply dictionary rules and substitution masks.
- Our analyzer calculates **Effective Entropy** by deducting penalties for dictionary words, sequences, and l33tspeak, revealing its true crackability in minutes.

| Strength Rating | Effective Entropy | Typical Crack Time (Fast GPU) |
|---|---|---|
| **VERY WEAK** | $< 25$ bits | Instant (< 1 millisecond) |
| **WEAK** | $25 - 44$ bits | Seconds to minutes |
| **MODERATE** | $45 - 64$ bits | Hours to days |
| **STRONG** | $65 - 84$ bits | Years to millennia |
| **VERY STRONG**| $\ge 85$ bits | Millions to trillions of years |

---

## 🧪 Running Unit Tests

Run the full test suite using Python's built-in `unittest`:

```bash
# Run with Python standard library
python3 -m unittest discover tests

# Or with uv
uv run python -m unittest discover tests
```

---

## 📂 Project Structure

```text
password-analyzer/
├── pyproject.toml            # Project packaging configuration (PEP 621)
├── README.md                 # Project documentation
├── DRAFT_POST.md             # Social media & community draft posts
├── sample_passwords.txt      # Sample list for batch testing
├── .gitignore
├── .python-version
├── src/
│   └── password_analyzer/
│       ├── __init__.py       # Package exports
│       ├── __main__.py       # python -m entry point
│       ├── main.py           # CLI entry point
│       ├── cli.py            # Argument parsing and dispatch
│       ├── models.py         # Dataclasses & enums
│       ├── entropy.py        # Shannon entropy calculation
│       ├── patterns.py       # L33t normalization & pattern detection
│       ├── leak_checker.py   # Breach database lookups
│       ├── analyzer.py       # Orchestrator & recommendation logic
│       └── formatter.py      # Console ANSI & table formatting
└── tests/
    ├── __init__.py
    ├── test_entropy.py       # Mathematical entropy tests
    ├── test_patterns.py      # Pattern and substitution tests
    └── test_analyzer.py      # Integration and end-to-end tests
```

---

## 👤 Author
**Sandeep Manchinasetti**  
- GitHub: [@sandeep2409-gitch](https://github.com/sandeep2409-gitch)
- Email: [sandeepmanchinasetti007@gmail.com](mailto:sandeepmanchinasetti007@gmail.com)
