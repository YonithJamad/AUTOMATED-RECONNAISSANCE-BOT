# Nikhal Tool Google Dorking

import requests
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, quote_plus
import socket
import re

def get_ip_info(target):
    try:
        # Prevent DNS resolve from hanging for minutes
        socket.setdefaulttimeout(3)
        ip = socket.gethostbyname(target)
        try:
            rdns = socket.gethostbyaddr(ip)[0]
        except:
            rdns = "N/A"
        return ip, rdns
    except:
        return "0.0.0.0", "N/A"

def check_robots(base):
    try:
        url = f"{base}/robots.txt"
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            return {"found": True, "url": url, "content": r.text[:500]}
    except:
        pass
    return {"found": False, "url": f"{base}/robots.txt", "content": ""}

def check_sitemap(base):
    try:
        url = f"{base}/sitemap.xml"
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            root = ET.fromstring(r.text)
            locations = [loc.text for loc in root.findall(".//{http://www.sitemaps.org/schemas/sitemap/0.9}loc")[:10]]
            return {"found": True, "entries": locations}
    except:
        pass
    return {"found": False, "entries": []}

def check_sensitive(base):
    files = [".env", ".git/config", "config.php", "backup.zip", "database.sql"]
    found = []
    for f in files:
        try:
            url = urljoin(base + "/", f)
            r = requests.get(url, timeout=2, verify=False)
            if r.status_code == 200:
                found.append(url)
        except:
            continue
    return found

def generate_dorks(domain):
    queries = [
        f"site:{domain} intitle:index.of",
        f"site:{domain} filetype:env",
        f"site:{domain} inurl:admin"
    ]
    return [{"query": q, "url": f"https://www.google.com/search?q={quote_plus(q)}"} for q in queries]


def run_search_engine_scan(target: str):
    if not target.startswith(("http://", "https://")):
        base_url = f"http://{target}"
        domain = target
    else:
        base_url = target.rstrip("/")
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]

    ip, rdns = get_ip_info(domain)

    response = {
        "target": target,
        "ip": ip,
        "rdns": rdns,
        "website": base_url,
        "search_engine": {
            "robots": check_robots(base_url),
            "sitemap": check_sitemap(base_url),
            "files": check_sensitive(base_url),
            "dorks": generate_dorks(domain)
        }
    }

    return response

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        print(run_search_engine_scan(sys.argv[1]))
    else:
        print("Please provide a target argument.")