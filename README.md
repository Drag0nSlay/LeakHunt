# 🚀 **LeakHunt v2.2.2 - Production Ready Secret Scanner**

**Independent secret scanner** for bug bounty hunters and security testers. Scans URLs, local files, and directories to detect exposed secrets using pattern matching, entropy analysis, and severity classification.

[![PyPI version](https://badge.fury.io/py/leakhunt.svg)](https://pypi.org/project/leakhunt/)
[![Tests](https://github.com/Drag0nSlay/LeakHunt/actions/workflows/test.yml/badge.svg)](https://github.com/Drag0nSlay/LeakHunt/actions)

## What's New in v2.2.2
- Full-secret preservation (no truncation) with masking moved strictly to display layer
- Added explainable detection output with score and reasons fields per finding
- Introduced hybrid scoring model combining pattern match, normalized entropy, and context signals
- Replaced binary entropy threshold logic with weighted confidence scoring system
- Added context-aware suppression for fake, test, dummy, example keywords
- Added lightweight token-shape filter to reduce placeholder-based false positives
- Implemented `detect_input_mode()` for automatic routing of file, URL, and raw text inputs
- Fixed `-U` misinterpretation of raw secret lists as fetch targets
- Improved CLI output consistency between `stdout` and `-o` JSON file export
- Added `--json` flag for structured machine-readable output (CI/SOC ready)
- Enhanced `--safe-mode` to only mask output layer without modifying internal detection values
- Improved entropy normalization for stable scoring across varying token lengths
- Added validation layer for ensuring pattern-triggered detections require minimum score thresholds
- Refactored scanner pipeline into `extraction → filtering → scoring → explanation` stages
- Improved logging clarity with severity + confidence visibility in verbose mode
- All existing CLI flags (`-f, -u, -U, -o, --patterns-dir`) remain fully backward compatible
- Test suite expanded for scoring engine, context filtering, and CLI output validation
- All tests passing (14 passed) and bytecode compilation verified via `python -m compileall leakhunt`

**Full history:** CHANGELOG.md

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
