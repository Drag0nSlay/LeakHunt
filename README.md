# 🔍 LeakHunt v2.1.2

LeakHunt is an **independent secret scanner** designed for bug bounty hunters and security testers.  
It scans URLs and local files to detect exposed secrets using pattern matching, entropy analysis, and severity classification.

Now with **deterministic output, stronger CLI validation, and improved error handling**, making it reliable for automation and pipelines.

---

## ✨ Features

- Independent scanning engine (no SecretFinder / LinkFinder dependency)
- Extended secret detection patterns:
  - GitHub tokens (`ghp_`, `github_pat_`)
  - Discord tokens  
  - Firebase keys  
  - OAuth Bearer tokens  
  - Private key blocks  
  - Mailgun / SendGrid / Twilio keys  

- 🧠 Entropy scoring to reduce weak false positives  
- 🔁 Deduplicated findings  
- ⚡ Multi-threaded fetching (`-t`)  
- 📥 Flexible input:
  - Single URLs
  - URL/file lists
  - Local files
  - Mixed targets  

- 📤 JSON export (`-o`)  
- 🐞 Verbose debug logging (`-v`)  
- 🚨 Severity classification (high / medium / low)

---

## 🆕 What’s New in v2.1.2

### 🔒 Stability & Error Handling
- Graceful handling of missing or unreadable target list files  
- Safe JSON output handling with clean error messages  
- No more unexpected CLI crashes  

### 🧪 CLI Improvements
- Strict validation for `--threads` (must be positive integer)  
- Clean argparse errors for invalid or non-numeric input  
- Programmatic CLI support via `parse_args(argv=...)`  

### ⚖️ Deterministic Output
- Stable ordering of scan results across runs  
- Fetch results preserve original target order  
- Consistent JSON output for automation & pipelines  

### 🧰 Testing Enhancements
- Added regression tests for:
  - Missing files  
  - Invalid output paths  
  - Invalid thread values  
  - Fetch order consistency  
  - Stable scan ordering  

- Test suite fully passing:
  - pytest -q 6 passed

---

## ⚙️ Installation

```bash
pip install -r requirements.txt
pip install .
```

## 🚀 CLI Usage

```bash
# mixed targets
leakhunt -t 8 -o findings.json https://example.com/app.js ./local.js

# multiple URLs
leakhunt -u https://example.com/app.js -u https://example.com/main.js

# targets from file
leakhunt -U lab/targets.txt -t 10 -v

# local files
leakhunt -f lab/index.html -f lab/test_private_key.txt
```

## 🧪 Local Testing Lab

1. Start a local server from repo root
2. In another terminal:
`leakhunt -U lab/targets.txt -t 5 -v -o lab/results.json`

**Lab includes:**
- `lab/index.html` → dummy tokens
- `lab/test_private_key.txt` → dummy private key

## ⚠️ Ethics Warning

> Use LeakHunt only on systems you own or have explicit authorization to test. Unauthorized scanning may violate laws and responsible disclosure policies.

## 📦 Release Notes

**v2.1.2**

- Deterministic scan result ordering
- Stable fetch order preservation
- Improved CLI argument validation
- Graceful error handling for file I/O
- Programmatic CLI support for testing
- Expanded regression test coverage

**v2.0.0**
- Full project refactor into package layout
- Independent scanning engine
- Multi-threaded fetching
- JSON reporting + severity summaries
- Local testing lab
