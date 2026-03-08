# Hemanandh Tool NIKTO

import subprocess
import re
from urllib.parse import urlparse

# ================= CONFIG =================
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
NIKTO_PATH = os.path.join(BASE_DIR, "nikto-master", "program", "nikto.pl")

def run_webanalysis_scan(raw_target):

    if raw_target.startswith(("http://", "https://")):
        parsed = urlparse(raw_target)
        target = parsed.hostname
    else:
        target = raw_target

    if not target:
        return {"error": "Invalid target"}

    # ================= RUN NIKTO =================
    cmd = [
        "perl",
        NIKTO_PATH,
        "-h", target,
        "-ssl",
        "-Tuning", "x",
        "-C", "all"
    ]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="ignore"
        )
        output = result.stdout
    except Exception as e:
        return {"error": str(e)}

    # ================= REGEX MAP =================
    regex_map = {

        # SSL / TLS
        "SLL Cipher": r"^\s*Ciphers:\s+(.+)",
        "SLL Issuer": r"^\s*Issuer:\s+(.+)",
        "SSL Certificate": r"SSL Info:\s+(.+)",
        "HTTP/3 (QUIC)": r"alt-svc.*HTTP/3",

        # Server & Headers
        "Web Server": r"^\s*\+\s*Server:\s+(.+)",
        "Server Banner": r"\+ Server:\s+(.+)",
        "Uncommon Header": r"Uncommon header\(s\)\s+'([^']+)'",
        "Missing Security Headers": r"Suggested security header missing:\s+([a-zA-Z\-]+)",
        "HSTS Missing": r"Strict-Transport-Security HTTP header is not defined",
        "X Content Type Option": r"X-Content-Type-Options header is not set",
        "Allowed HTTP Methods": r"Allowed HTTP Methods:\s+(.+)",

        # Scan Info
        "Nikto Version": r"^- Nikto v([\d\.]+)",
        "Start Time": r"\+ Start Time:\s+(.+)",
        "End Time": r"\+ End Time:\s+(.+?)(?:\s*\(\d+\s+seconds?\))?$",
        "Scan Duration": r"\+ End Time:.+?\((\d+\s+seconds?)\)",

        # Target Info
        "Multiple IPs": r"Multiple IPs found:\s+(.+)",
        "Target IP": r"Target IP:\s+([\d\.]+)",
        "Target Hostname": r"Target Hostname:\s+(.+)",
        "Target Port": r"Target Port:\s+(\d+)",

        # Vulnerabilities / Findings
        "Generic Finding": r"^\s*\+\s+(/[^\s]*):\s+(.+)",
        "OSVDB Vulnerability": r"OSVDB-\d+:\s+(.+)",
        "Directory Indexing": r"Directory indexing found",
        "Interesting File": r"\+ (/[^\s]+): This might be interesting",
        "CGI Script": r"/cgi-bin/[^\s]+",
        "Redirect Found": r"redirected to\s+(.+)",
        "HTTP Error": r"returned a HTTP error:\s+(\d+)",
        "Server Outdated": r"Server may be outdated",

        # Cookie Issues
        "Cookie Without Secure Flag": r"Cookie\s+([^\s]+)\s+created without the secure flag",
        "Cookie Without HttpOnly": r"Cookie\s+([^\s]+)\s+created without the httponly flag",

        # Backup / Admin
        "Backup File": r"\.(bak|old|backup|zip|tar|gz)",
        "Admin Panel": r"/admin|/administrator|/login",

        # Errors
        "SSL Handshake": r"handshake failure",
        "Error Limit Reached": r"ERROR: Error limit",
        "Socket Error": r"already connected socket",
        "Nikto Plugin Error": r"nikto.*\.pm line \d+",
    }

    parsed_data = {}

    for title, pattern in regex_map.items():
        matches = re.findall(pattern, output, re.MULTILINE | re.IGNORECASE)
        if matches:
            parsed_data[title] = matches

    # ================= FORMAT FUNCTION =================
    def format_list(keys):
        items = []
        for key in keys:

            if key in parsed_data:

                val_list = []

                for match in parsed_data[key][:50]:

                    item_text = " | ".join(match) if isinstance(match, tuple) else match

                    val_list.append(
                        f'<div class="mb-2 pb-1 border-bottom border-secondary border-opacity-25">{item_text}</div>'
                    )

                if len(parsed_data[key]) > 50:
                    val_list.append(
                        f'<div class="text-muted fst-italic">...and {len(parsed_data[key]) - 50} more</div>'
                    )

                val = "".join(val_list)

            else:
                val = "---"

            items.append({"label": key, "value": val})

        return items

    # ================= FINAL DATA =================
    final_data = {
        # Scan Info
        "scan_info": format_list([
            "Nikto Version",
            "Start Time",
            "End Time",
            "Scan Duration"
        ]),

        # Target Info
        "target_details": format_list([
            "Multiple IPs",
            "Target IP",
            "Target Hostname",
            "Target Port"
        ]),


         # SSL
        "ssl_info": format_list([
            "SLL Cipher",
            "SLL Issuer",
            "SSL Certificate",
            "HTTP/3 (QUIC)"
        ]),

        # Headers
        "header_info": format_list([
            "Web Server",
            "Server Banner",
            "Uncommon Header",
            "Missing Security Headers",
            "HSTS Missing",
            "X Content Type Option",
            "Allowed HTTP Methods"
        ]),

        # Vulnerabilities
        "findings": format_list([
            "Generic Finding",
            "OSVDB Vulnerability",
            "Directory Indexing",
            "Interesting File",
            "Admin Panel",
            "Backup File",
            "CGI Script",
            "Redirect Found",
            "HTTP Error",
            "Server Outdated"
        ]),

        # Cookies
        "cookie_issues": format_list([
            "Cookie Without Secure Flag",
            "Cookie Without HttpOnly"
        ]),

        # Errors
        "errors": format_list([
            "SSL Handshake",
            "Error Limit Reached",
            "Socket Error",
            "Nikto Plugin Error"
        ]),
        "summary": "Scan completed successfully."
    }

    final_data = {k: v for k, v in final_data.items() if v is not None}

    return {"website_analysis": final_data}

# ================= CLI MODE =================
if __name__ == "__main__":

    raw_target_input = input("Enter IP / domain / URL: ").strip()

    print("\n========== NIKTO OUTPUT ==========\n")

    results = run_webanalysis_scan(raw_target_input)

    if "error" in results:
        print(f"Error: {results['error']}")

    else:

        for title, matches in results.items():

            print(f"{title}:")

            for match in matches:

                if isinstance(match, tuple):
                    print(" | ".join(match))

                else:
                    print(match)

            print()