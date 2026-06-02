# 🚀 **LeakHunt v2.2.0 - Production Ready Secret Scanner**

**Independent secret scanner** for bug bounty hunters and security testers. Scans URLs, local files, and directories to detect exposed secrets using pattern matching, entropy analysis, and severity classification.

[![PyPI version](https://badge.fury.io/py/leakhunt.svg)](https://pypi.org/project/leakhunt/)
[![Tests](https://github.com/Drag0nSlay/LeakHunt/actions/workflows/test.yml/badge.svg)](https://github.com/Drag0nSlay/LeakHunt/actions)

## 🆕 What's New in v2.2.1
- CI pipeline now passing on Python 3.9, 3.10, 3.11, 3.12
- Added pip caching and retry logic to GitHub Actions workflow
- Fixed lab/targets.txt missing on CI runners (auto-created in workflow)
- Bumped GitHub Actions to Node.js 24 compatible versions

## 🆕 What’s New in v2.2.0 (Feature List)

### Core Detection Features
- ✅ 12+ Production Patterns
   - GitHub Tokens (ghp_, github_pat_)
   - AWS Access Keys (AKIA...)
   - Generic API Keys (api_key=, token=)
   - Slack/Discord Tokens
   - Private Keys (RSA/ECDSA)
   - JWT Tokens
   - Mailgun/SendGrid/Twilio
   - Firebase Keys

- ✅ Shannon Entropy Analysis (3.5 default)
- ✅ Severity Classification (high/medium/low)
- ✅ False Positive Reduction
- ✅ Deterministic Ordering

### Performance Features
- ✅ Multi-Threaded Fetching (-t 15)
- ✅ Progress Bars (tqdm) 
- ✅ Memory Efficient Processing
- ✅ Stable Result Ordering
- ✅ Graceful Error Handling
- ✅ Thread-Safe Operations

### Security & Privacy
- ✅ SAFE MODE (--safe-mode)
   - ghp_abcde...f123 (masked)
   - AKIAIOSF...MPLE (masked)
   - No secret exposure in logs
   
- ✅ No External Dependencies
- ✅ No Network Calls During Scan
- ✅ Clean Error Messages

### CLI Features
- ✅ Input Flexibility
   - **Positional:** leakhunt file.txt url.com
   - **URLs:** -u url -u url2
   - **URL File:** -U targets.txt
   - **Files:** -f file1 -f file2

- ✅ Output Options
   - Console (colored/rich)
   - JSON Export (-o results.json)
   - Verbose Debug (-v)
   - No Color (--no-color)

- ✅ Configuration
   - --entropy-threshold 3.0
   - --patterns-dir patterns/
   - --threads 10
   - --dry-run (validate only)
 
### Extensibility
✅ YAML Pattern System
   ```bash
   patterns/
   ├── api_keys.yaml
   ├── generic.yaml
   └── custom.yaml
```

✅ Pattern Format
```yaml
- name: "Stripe API Key"
  regex: "sk_live_[0-9a-zA-Z]{24,}"
  severity: "high" 
  entropy_required: false
```

### Testing & Validation
- ✅ Local Lab Included
```bash
   lab/
   ├── targets.txt
   ├── index.html (GitHub tokens)
   └── test_private_key.txt
```

- ✅ Dry Run Mode
- ✅ Regression Test Suite
- ✅ All Tests Passing
- ✅ Deterministic Output

## Detection Matrix

| Pattern Type | Example Match  | Severity | Entropy Filter |
| ------------ | -------------- | -------- | -------------- |
| GitHub Token | ghp_xxxxxxxxxx | HIGH     | ❌ No           |
| AWS Key      | AKIAxxxxxxxxxx | HIGH     | ❌ No           |
| API Key      | api_key="xxx"  | MEDIUM   | ❌ No           |
| JWT          | eyJxxxxx.xxx   | MEDIUM   | ✅ Yes          |
| Slack        | xoxb-xxxx      | HIGH     | ❌ No           |

---

## 🆕 What’s New in v2.1.2 (Old Version)

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

## 📦 Release Notes

**v2.2.0**

- **SAFE MODE -** Masks secrets: ghp_abcde...f123
- **GENERIC API KEYS -** api_key="123456..."
- **PROGRESS BARS -** Real-time fetching status
- **DRY RUN -** Validate targets without scanning
- **YAML PATTERNS -** Extensible pattern system
- **12+ PRODUCTION PATTERNS -** GitHub, AWS, Slack+
- **GIT BUG BOUNTY READY -** Deterministic output

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
