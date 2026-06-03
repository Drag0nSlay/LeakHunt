# Changelog
## 🆕 What's New in v2.2.2
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

## 🆕 What's New in v2.2.1
- Pluggable pattern loading via leakhunt.patterns module
- load_patterns with DEFAULT_PATTERNS_DIR and SecretPattern dataclass
- YAML pattern loader with sorted *.yaml discovery and hardcoded fallback
- Generic regexes now support spaces around =/: and secrets up to 128 chars
- Scanner accepts optional patterns parameter for custom pattern sets
- CLI --patterns-dir flag wires custom patterns directly into scan_many
- Fixed api_key = "..." (spaced assignment) detection
- CI pipeline hardened across Python 3.9, 3.10, 3.11, 3.12
- Added pip caching and retry logic to GitHub Actions workflow
- Fixed lab/targets.txt missing on CI runners (auto-created in workflow)
- All tests passing across all supported Python versions

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
