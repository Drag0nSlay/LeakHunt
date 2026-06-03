# 🚀 **LeakHunt v2.2.1 - Production Ready Secret Scanner**

**Independent secret scanner** for bug bounty hunters and security testers. Scans URLs, local files, and directories to detect exposed secrets using pattern matching, entropy analysis, and severity classification.

[![PyPI version](https://badge.fury.io/py/leakhunt.svg)](https://pypi.org/project/leakhunt/)
[![Tests](https://github.com/Drag0nSlay/LeakHunt/actions/workflows/test.yml/badge.svg)](https://github.com/Drag0nSlay/LeakHunt/actions)

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

# Bug Bounty
leakhunt --safe-mode -t 15 -U targets.txt -o findings.json -v

# Lab Testing  
leakhunt --safe-mode -U lab/targets.txt

# Custom Patterns
leakhunt --patterns-dir patterns/ test.txt

# Dry Run
leakhunt --dry-run -U urls.txt

# Low Entropy
leakhunt --entropy-threshold 3.0 --safe-mode files/
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
