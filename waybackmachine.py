# Sai Ganesh Tool WaybackMachine

import requests
import re
import sys
import json
import urllib3
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

API_REGEX = re.compile(r"api|v[0-9]|graphql|json|ajax", re.I)
SENSITIVE_REGEX = re.compile(r"admin|login|portal|config|env|secret|staff|erp|auth|dashboard|internal|private|backup|sql|db|git|jenkins|jira", re.I)

def get_wayback_data(domain):
    clean_domain = domain.replace("http://", "").replace("https://", "").replace("www.", "").split('/')[0]
    
    cdx_url = f"http://web.archive.org/cdx/search/cdx?url=*.{clean_domain}/*&output=text&fl=original&collapse=urlkey"

    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[502, 503, 504],
        allowed_methods=["GET"]
    )
    session.mount("http://", HTTPAdapter(max_retries=retry_strategy))
    session.mount("https://", HTTPAdapter(max_retries=retry_strategy))

    try:
        response = session.get(cdx_url, timeout=60, verify=False)
        response.raise_for_status()
        
        all_urls = response.text.splitlines()
        total_count = len(all_urls)

        if total_count == 0:
            return {"web_hub": {"api": [], "sensitive": [], "others": []}}

        api_list = sorted(list({u for u in all_urls if API_REGEX.search(u)}))
        sens_list = sorted(list({u for u in all_urls if SENSITIVE_REGEX.search(u)}))
        others = sorted(list({u for u in all_urls if not API_REGEX.search(u) and not SENSITIVE_REGEX.search(u)}))

        return {
            "web_hub": {
                "api": api_list[:500],
                "sensitive": sens_list[:500],
                "others": others[:500]
            }
        }

    except Exception as e:
        return {"web_hub": {"api": [], "sensitive": [], "others": []}}

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else input("Enter Domain (e.g., example.com): ").strip()
    if not target:
        print("[-] No domain provided.")
        return

    data = get_wayback_data(target)

    print(f"\n{'#' * 30} RESULTS FOR {target} {'#' * 30}")
    
    web_hub = data.get("web_hub", {})
    
    print(f"\n[+] SENSITIVE ENDPOINTS ({len(web_hub.get('sensitive', []))})")
    for i, url in enumerate(web_hub.get('sensitive', [])[:50], 1):
        print(f"  [{i}] {url}")
    
    print(f"\n[+] API ENDPOINTS ({len(web_hub.get('api', []))})")
    for i, url in enumerate(web_hub.get('api', [])[:50], 1):
        print(f"  [{i}] {url}")

    print(f"\n[+] OTHER URLS ({len(web_hub.get('others', []))})")
    for i, url in enumerate(web_hub.get('others', [])[:50], 1):
        print(f"  [{i}] {url}")

    print(f"\n{'#' * 75}\n")

if __name__ == "__main__":
    main()