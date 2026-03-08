# Idris & Sweety Tool Wappalyzer

import socket
import requests
import warnings
from Wappalyzer import Wappalyzer, WebPage

# Suppress ResourceWarnings and SSL/Insecure warnings
warnings.filterwarnings("ignore", category=ResourceWarning)
# Suppress the Wappalyzer regex warning
warnings.filterwarnings("ignore", message=r"Caught 'unbalanced parenthesis", category=UserWarning)
# Suppress general insecure request warnings
warnings.filterwarnings("ignore")

def get_banner(url, port=80):
    """Performs traditional Banner Grabbing using sockets."""
    try:
        # Strip protocol for socket connection
        host = url.replace("https://", "").replace("http://", "").split('/')[0]
        s = socket.socket()
        s.settimeout(2)
        s.connect((host, port))
        
        # Send a basic HTTP request to provoke a response
        s.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
        response = s.recv(1024).decode(errors='ignore')
        s.close()
        
        banner = response.split('\n')
        # Look for the 'Server' line in the header
        for line in banner:
            if "Server:" in line:
                return line.strip().replace("Server: ", "")
        return "No server banner found."
    except Exception as e:
        return f"Could not grab banner: {e}"

def get_wappalyzer_data(target):
    """
    Dashboard Integration: Aggregates tech stack, CMS, services, and frameworks.
    """
    if not target.startswith(('http://', 'https://')):
        url = 'https://' + target
    else:
        url = target

    results_data = {
        "banner": "N/A",
        "services": "None detected",
        "languages": "None detected",
        "frameworks": "None detected",
        "cms": "None detected",
        "other_techs": "None detected"
    }

    try:
        # 1. Traditional Banner Grabbing
        results_data["banner"] = get_banner(url)

        # 2. Wappalyzer Analysis
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'
        }
        # Using verify=False to avoid SSL issues during scanning
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage(url=url, html=response.text, headers=response.headers)
        detected_with_cats = wappalyzer.analyze_with_categories(webpage)
        
        all_techs = set(detected_with_cats.keys())

        # --- Categorization ---
        cms_found = []
        frameworks_found = []
        languages_found = []
        
        target_services = {"apache", "nginx", "iis", "litespeed", "caddy", "cloudflare", "google web server", "amazon s3"}
        services_found = [tech for tech in all_techs if tech.lower() in target_services]

        target_framework_cats = {"Web frameworks", "JavaScript frameworks", "Mobile frameworks", "Page builders", "Static site generator", "UI frameworks"}
        target_languages = {"PHP", "Python", "Java", "C#", "Ruby", "Go", "Groovy", "Scala", "Kotlin", "Objective-C", "Hack", "Elixir", "Erlang", "Haskell", "Dart", "Crystal", "Nim", "ColdFusion", "JavaScript", "TypeScript", "Node.js", "Deno", "Apex", "ABAP", "COBOL", "PowerShell", "PL/SQL", "T-SQL", "Rust", "Zig", "V", "Julia", "OCaml"}

        for tech, info in detected_with_cats.items():
            cats = set(info.get('categories', []))
            
            if 'CMS' in cats:
                cms_found.append(tech)
            
            if cats.intersection(target_framework_cats):
                frameworks_found.append(tech)
            
            if "Programming languages" in cats or tech in target_languages:
                languages_found.append(tech)

        # --- Manual Fallback Detection for Frameworks ---
        html_lower = response.text.lower()
        manual_frameworks = {
            "Next.js": ["_next/static", "next-head-count", "__next"],
            "Tailwind CSS": ["tailwind", "--tw-"],
            "React": ["react-root", "data-reactroot", "react.development.js"],
            "Vite": ["vite/client", "@vite"],
            "Astro": ["astro-", "data-astro"],
            "Alpine.js": ["x-data=", "x-init="],
        }

        for tech, patterns in manual_frameworks.items():
            if any(p in html_lower for p in patterns):
                if tech not in frameworks_found:
                    frameworks_found.append(tech)

        # Update results_data with joined strings
        if services_found: results_data["services"] = ", ".join(sorted(services_found))
        if languages_found: results_data["languages"] = ", ".join(sorted(set(languages_found)))
        if frameworks_found: results_data["frameworks"] = ", ".join(sorted(set(frameworks_found)))
        if cms_found: results_data["cms"] = ", ".join(sorted(cms_found))
        if all_techs: results_data["other_techs"] = ", ".join(sorted(all_techs))

    except Exception as e:
        # print(f"Error in wappalyzer_data: {e}")
        # We still return the partial results or the default "None detected"
        pass

    return {"web_hub": results_data}

# User's CLI compatibility logic
def run_wappalyzer(url):
    try:
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url(url)
        techs = wappalyzer.analyze(webpage)
        return techs
    except Exception as e:
        return f"Wappalyzer error: {e}"

def banner_logic(target_url):
    print("\n--- Banner Grabbing & Tech Stack ---")
    print(f"[+] Banner: {get_banner(target_url)}")
    print("[+] Technologies detected:")
    technologies = run_wappalyzer(target_url)
    if isinstance(technologies, set):
        for tech in technologies:
            print(f"  - {tech}")
    else:
        print(f"  {technologies}")

def detect_cms(target_url):
    print("\n--- CMS Detection ---")
    try:
        res = get_wappalyzer_data(target_url)
        cms = res["web_hub"]["cms"]
        if cms != "None detected":
            print(f"CMS Detected: {cms}")
        else:
            print("No specific CMS detected (The site might be custom-built).")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def scan_user_url(target_url):
    print("\n--- Web Service Detection ---")
    try:
        res = get_wappalyzer_data(target_url)
        services = res["web_hub"]["services"]
        if services != "None detected":
            print(f"Match(es) found: {services}")
        else:
            print("None of the specified services were detected.")
    except Exception as e:
        print(f"An error occurred: {e}")

def scan_frameworks_and_languages(target_url):
    print("\n--- Framework & Language Analysis ---")
    try:
        res = get_wappalyzer_data(target_url)
        frameworks = res["web_hub"]["frameworks"]
        languages = res["web_hub"]["languages"]
        
        if frameworks != "None detected":
            print("[+] Frameworks/CMS Detected:")
            for item in frameworks.split(", "):
                print(f"    - {item}")
        else:
            print("[-] No listed frameworks or CMS detected.")

        if languages != "None detected":
            print(f"\n[+] Programming Languages Detected: {languages}")
        else:
            print("\n[-] No listed programming languages detected.")
    except Exception as e:
        print(f"[!] Critical Error: {e}")

if __name__ == "__main__":
    url = input("Enter the website URL to scan: ").strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    print(f"\nStarting comprehensive scan for: {url}")
    banner_logic(url)
    detect_cms(url)
    scan_user_url(url)
    scan_frameworks_and_languages(url)
