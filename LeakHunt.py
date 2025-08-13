import argparse
import subprocess
import sys
import re
import os

GREEN = "\033[92m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def colorize(line):
    original_line = line.rstrip("\n")

    if "[ + ] SCANNING URL:" in original_line:
        line = original_line.replace("[ + ] SCANNING URL:", f"{GREEN}[ + ] SCANNING URL:{RESET}")

    elif "[ + ] URL:" in original_line:
        line = original_line.replace("[ + ] URL:", f"{BLUE}[ + ] URL:{RESET}")

    if re.search(r"\b(api|key|token|secret)\b", original_line, re.IGNORECASE):
        line = re.sub(r"\b(api|key|token|secret)\b", f"{YELLOW}\\1{RESET}", line, flags=re.IGNORECASE)

    return line

def main():
    parser = argparse.ArgumentParser(description="Scan all URLs with colorized output")
    parser.add_argument("-f", "--file", required=True, help="File containing URLs")
    parser.add_argument("-p", "--prefix", default="", help="Prefix to add to relative URLs")
    parser.add_argument("-t", "--tool", required=True, help="Path to SecretFinder or other tool")
    parser.add_argument("-a", "--args", default="", help="Extra arguments for the tool")
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"[!] File not found: {args.file}")
        sys.exit(1)

    urls = []
    with open(args.file, "r") as infile:
        for line in infile:
            url = line.strip()
            if not url:
                continue
            if not url.startswith(("http://", "https://")) and args.prefix:
                url = args.prefix.rstrip("/") + "/" + url.lstrip("/")
            urls.append(url)

    if not urls:
        print("[!] No valid URLs found.")
        sys.exit(1)
        
    for js_url in urls:
        print(f"{GREEN}[ + ] SCANNING URL: {js_url}{RESET}")
        process = subprocess.Popen(
            [sys.executable, args.tool, "-i", js_url, "-o", "cli"] + args.args.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        for line in process.stdout:
            print(colorize(line))

        process.wait()
        print() 

if __name__ == "__main__":
    main()
