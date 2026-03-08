import dns.resolver
import requests
import socket
import random
import string

class AmassPythonClone:
    def __init__(self, domain):
        self.domain = domain
        self.ssl_san_entries = set()        
        self.wildcard_detected = False      
        self.active_subdomains = {}         
        self.historical_domains = set()      
        self.takeover_candidates = {}       

    def detect_wildcard(self):
        """Detects if the domain has a Wildcard DNS enabled"""
        random_sub = "".join(random.choices(string.ascii_lowercase, k=12)) + "." + self.domain
        try:
            dns.resolver.resolve(random_sub, 'A')
            self.wildcard_detected = True
            # print(f"[!] WARNING: Wildcard DNS detected on {self.domain}.")
        except:
            self.wildcard_detected = False
            # print("[+] No Wildcard DNS detected.")

    def passive_discovery(self):
        """Collects ALL SSL SAN Entries using crt.sh"""
        # print(f"[*] Fetching SSL SAN Entries from CT logs (this may take a moment)...")
        url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        
        try:
            with requests.Session() as session:
                retries = requests.adapters.Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
                session.mount('https://', requests.adapters.HTTPAdapter(max_retries=retries))
                response = session.get(url, headers=headers)
                if response.status_code == 200:
                    try:
                        data = response.json()
                        for entry in data:
                            name = entry['name_value'].lower()
                            for sub in name.split('\n'):
                                if not sub.startswith('*.'):
                                    self.ssl_san_entries.add(sub)
                        # print(f"[+] Successfully gathered {len(self.ssl_san_entries)} unique SAN entries.")
                    except ValueError:
                        # print(f"[-] Error: Could not parse JSON response from crt.sh. Response content: {response.text[:100]}...")
                        pass
                else:
                    # print(f"[-] Error: crt.sh returned status code {response.status_code}")
                    pass
        except Exception as e:
            # print(f"[-] Passive discovery failed: {e}")
            pass

    def check_takeover(self, subdomain):
        takeover_signatures = {
            "github.io": "GitHub Pages",
            "herokudns.com": "Heroku",
            "s3.amazonaws.com": "AWS S3 Bucket",
            "azurewebsites.net": "Azure App Service"
        }
        try:
            answers = dns.resolver.resolve(subdomain, 'CNAME')
            for rdata in answers:
                cname = str(rdata.target).lower()
                for sig, provider in takeover_signatures.items():
                    if sig in cname:
                        self.takeover_candidates[subdomain] = f"{provider} ({cname})"
                        return True
        except:
            pass
        return False

    def process_subdomains(self):
        # print("[*] Processing all entries for resolution and takeover checks...")
        for sub in sorted(self.ssl_san_entries):
            self.check_takeover(sub)
            try:
                addr = socket.gethostbyname(sub)
                self.active_subdomains[sub] = addr
            except (socket.gaierror, socket.timeout):
                self.historical_domains.add(sub)

    def display_results(self):
        pass

    def get_results(self):
        """Returns the collected data as a dictionary"""
        return {
            "wildcard_detected": self.wildcard_detected,
            "ssl_san_entries": sorted(list(self.ssl_san_entries)),
            "active_subdomains": self.active_subdomains,
            "historical_domains": sorted(list(self.historical_domains)),
            "takeover_candidates": self.takeover_candidates
        }

    def run(self):
        self.detect_wildcard()
        self.passive_discovery()
        self.process_subdomains()
        self.display_results()

def run_subdomain_scan(target):
    # print(f"[*] Starting Subdomain Scan for {target}...")
    scanner = AmassPythonClone(target)
    scanner.run()
    return {
        "sub_domain": scanner.get_results()
    }

if __name__ == "__main__":
    target = input("Enter target domain: ").strip()
    if target:
        scanner = AmassPythonClone(target)
        scanner.run()