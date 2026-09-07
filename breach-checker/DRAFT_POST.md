# Draft Social Media Posts (Day 3: Email & Username Breach Checker)

Here are ready-to-use draft posts for LinkedIn, Twitter / X, and developer communities.

---

## 🚀 Option 1: LinkedIn / Dev.to / Blog (Story-Driven & Technical)

**Headline:** Day 3 of #30DaysOfPython: Building a Data Breach Checker CLI 🔍🛡️

Have you ever wondered how many data breaches your old email addresses or usernames have ended up in?

For Day 3 of my **#30DaysOfPython** challenge, I built **Breach Checker** — a command-line security tool that checks accounts against millions of leaked records using public breach APIs.

💡 **The Curveball:**
When planning to use the Have I Been Pwned (HIBP) API, I noticed HIBP’s breach endpoint now requires a paid API key. Rather than locking the project behind a paywall, I designed a **dual-provider client**:
1. **XposedOrNot API (Default & Free)**: Enables instant email breach lookups out-of-the-box with **zero API key required**.
2. **Have I Been Pwned (HIBP v3)**: Seamlessly activated whenever an API key is provided, unlocking HIBP's massive dataset and username search.

🛠️ **Key Features:**
- 🖥️ **Dual Modes**: Interactive terminal menu for quick one-off lookups + CLI flags (`-t`, `-f`, `-o`) for automation scripts.
- 📁 **Batch File Scanning**: Reads targets from `.txt` or `.csv` files and audits entire team lists or credential dumps.
- ⏱️ **Polite Rate Pacing**: Built-in delay mechanism between requests so queries don't hit public API rate limits (HTTP 429).
- 📊 **Multi-Format Export**: Generates structured reports in `.json`, spreadsheet-ready `.csv`, or formatted `.txt`.
- ⚡ **Zero Heavy Dependencies**: Built purely with Python 3’s standard library (`urllib.request`, `json`, `csv`, `argparse`, `dataclasses`).

🧪 **Testing & Quality:**
Shipped with 20 unit tests using `unittest.mock` to simulate HTTP 200, 404 (clean accounts), 401 (unauthorized), and 429 (rate-limited) responses without hitting external networks.

👉 When was the last time you checked if your email was in a breach? Let me know in the comments!

#Python #CyberSecurity #CodingChallenge #OpenSource #SoftwareEngineering #30DaysOfPython #DataPrivacy #InfoSec

---

## ⚡ Option 2: Twitter / X Thread (Punchy & Engaging)

**1/4:** 🚨 Day 3 of #30DaysOfPython: Email & Username Breach Checker!

Built a CLI tool that queries public breach APIs to see if your accounts were exposed in data leaks.

Here's how I handled the HIBP API paywall and built it with pure Python 🧵👇

**2/4:** 💡 The Challenge:
HIBP's breach API requires a paid key now.

The Solution: A dual-provider architecture!
• Default: Free public lookups via XposedOrNot (no API key needed)
• Optional: HIBP v3 when you pass an API key

Best of both worlds! 🚀

**3/4:** 🛠️ Features:
• Interactive menu or CLI flags (`-t`, `-f`, `-o`)
• Batch audit from `.txt` or `.csv` files
• Rate limit pacing to avoid HTTP 429s
• Export to JSON, CSV, or formatted TXT
• 0 external dependencies (pure stdlib)
• 20 unit tests with mocked APIs

**4/4:** How many breaches is your primary email in? (Mine was in 4... time to rotate passwords 😅).

Repo & Code: [GitHub link]

#Python #DevCommunity #CyberSecurity #100DaysOfCode

---

## 📌 Option 3: Quick GitHub Release Notes / Status Update

**Day 3: Email & Username Breach Checker Released!**
- Query emails & usernames against known breach databases.
- Supports both XposedOrNot (free, zero-config) and HIBP v3 (API key).
- Batch target list auditing with rate limiting.
- Export results directly to CSV or JSON.
- 100% test coverage on standard library client & models.

