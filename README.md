# 🔍 LeakHunt
## Advanced Secret Discovery & API Key Exposure Detection Tool

LeakHunt is a lightweight yet powerful **secret scanning utility** designed for penetration testers, bug bounty hunters, and security researchers.
It leverages robust detection engines from [SecretFinder](https://github.com/m4ll0k/SecretFinder) and enhances them with additional features, making it easier to identify **API keys, tokens, endpoints, and sensitive information** from JavaScript files and web assets.

---
## ✨ Features:
- 🚀 **High-Accuracy Secret Detection** – Finds API keys, tokens, and credentials hidden inside JS files.
- 🌐 **Multiple Input Options** – Works with URLs, local files, and bulk lists.
- 🎯 **Integration-Ready** – Can be used alongside other tools like [LinkFinder](https://github.com/GerbenJavado/LinkFinder) for deeper asset mapping.
- 🖥 **Color-Coded Output** – Readable CLI output for quick analysis.
- ⚡ **Fast & Lightweight** – Minimal dependencies, quick execution.


## 📌 Use Cases:
- **Bug Bounty Hunting** – Scan target JavaScript files for secrets before reporting vulnerabilities.

- **Penetration Testing** – Automate sensitive information discovery during engagements.

- **Security Audits** – Ensure no hardcoded keys or tokens are left exposed in production.

## 🛠 Installation:
```bash
# Clone this repository
git clone https://github.com/Drag0nSlay/LeakHunt.git
cd LeakHunt

# Install dependencies
pip install -r requirements.txt
