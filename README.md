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

---

## 📌 Use Cases:
- **Bug Bounty Hunting** – Scan target JavaScript files for secrets before reporting vulnerabilities.

- **Penetration Testing** – Automate sensitive information discovery during engagements.

- **Security Audits** – Ensure no hardcoded keys or tokens are left exposed in production.

## 🛠 Installation & Setup:
  **1. Clone this repository**
``` bash 
git clone https://github.com/m4ll0k/SecretFinder.git
# or
git clone https://github.com/GerbenJavado/LinkFinder.git
```
  **2. Open the Repository Folder**
``` bash
cd SecretFinder   # or LinkFinder
```
  **3. Create LeakHunt.py**
``` bash
nano LeakHunt.py
```
*(Or use vim LeakHunt.py if you prefer)*

  **4. Copy & paste the LeakHunt script** into the editor, then save and exit.

   - **In nano:** Press ```CTRL + O``` to save, ```Enter``` to confirm, and ```CTRL + X``` to exit.

   - **In vim:** Press ```Esc```, then type ```:wq``` and hit ```Enter```.

**5. Install Dependencies:**
```
pip install -r requirements.txt
```
---     

## 🚀 Usage
```bash
python3 LeakHunt.py -f js_files.txt -t secretfinder/SecretFinder.py -a "-o cli"
```

## 💡 Pro Tip
You can combine LeakHunt with [LinkFinder](https://github.com/GerbenJavado/LinkFinder) to first extract all JavaScript endpoints from a target and then run LeakHunt for maximum coverage.

## ⚖ License
This project is released under the [MIT License](https://github.com/Drag0nSlay/LeakHunt/tree/main?tab=MIT-1-ov-file) – see the LICENSE file for details.

## 🙏 Credits
LeakHunt’s detection capabilities are powered by:
- [SecretFinder](https://github.com/m4ll0k/SecretFinder) – Core secret detection engine.
- [LinkFinder](https://github.com/GerbenJavado/LinkFinder) – For endpoint discovery (optional integration).

## 📢 Disclaimer
This tool is intended **for educational and authorized security testing only.**
Unauthorized use of this tool against systems without prior consent is **illegal.**

---
## 🚀 Future Plans

- Make LeakHunt a fully independent tool (no dependency on SecretFinder/LinkFinder).
- Add a PyPI package for one-command installation (`pip install leakhunt`).
- Implement additional secret detection patterns (API keys, tokens, etc.).
- Add multi-threaded scanning for faster results.
<!-- Create a GUI version of LeakHunt.
