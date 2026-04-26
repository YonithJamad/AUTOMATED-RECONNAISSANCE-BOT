from fastapi import APIRouter, Request, Query, Depends, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
import socket
import re
import subprocess
import platform
import os
import json
import datetime
import logging

logger = logging.getLogger(__name__)

# Strict allowlist: hostname, IPv4, or CIDR — blocks all shell metacharacters
VALID_TARGET_RE = re.compile(
    r'^(?:'
    r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'  # hostname
    r'|(?:\d{1,3}\.){3}\d{1,3}'            # IPv4
    r'|(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}'   # CIDR
    r')$'
)

def require_login(request: Request):
    """FastAPI dependency — rejects unauthenticated requests with HTTP 401."""
    if not request.session.get("user"):
        raise HTTPException(status_code=401, detail="Unauthorized")
import network_logic
import subdomain_logic
import email_logic
import search_logic
import initial_logic
import webhub_logic
import webanalysis_logic
import udp_logic

router = APIRouter()
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
SCAN_DATA_DIR = os.path.join(BASE_DIR, "scan_data")

def _reverse_dns(ip: str, timeout: float = 3.0):
    """Thread-safe reverse DNS — avoids mutating the global socket timeout."""
    from concurrent.futures import ThreadPoolExecutor, TimeoutError as _TE
    with ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(socket.gethostbyaddr, ip)
        try:
            return fut.result(timeout=timeout)[0]
        except (_TE, OSError):
            return None

def normalize_target(target, target_type="website"):
    if target_type == "website":
        # Remove schema and trailing paths
        target = target.replace("https://", "").replace("http://", "")
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", target):
            target = target.split("/")[0]

    # IP RESOLUTION: If it's a bare IP (not CIDR), try to resolve it to a domain
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
        resolved = _reverse_dns(target)
        if resolved:
            return resolved
    return target

def get_canonical_type(scan_type):
    """
    Standardizes scan type aliases to unified internal keys for consistent caching and filenames.
    """
    if not scan_type:
        return scan_type
        
    scan_type = scan_type.lower().strip()
    if scan_type == "all":
        return "all"
        
    canonical_input = scan_type.replace(" ", "").replace("_", "")
    
    # Mapping aliases and substrings to standardized keys
    type_mapping = {
        "initial": "initial",
        "subdomain": "subdomain",
        "webhub": "webhub",
        "search": "search",
        "email": "email",
        "network": "network",
        "udp": "udp",
        "webanalysis": "webanalysis",
        "website": "webanalysis"
    }
    
    for key, val in type_mapping.items():
        if key in canonical_input:
            return val
            
    return scan_type.replace(" ", "_")

@router.get("/dashboard")
async def serve_dashboard(request: Request):
    if not request.session.get("user"):
        response = RedirectResponse(url="/login", status_code=303)
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
        return response
    return templates.TemplateResponse("index.html", {"request": request})

@router.get("/ping")
async def check_ping_endpoint(target: str, _=Depends(require_login)):
    if not VALID_TARGET_RE.match(target):
        return {"error": "Invalid target"}
    # Resolve IP if needed
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
        resolved = _reverse_dns(target)
        if resolved:
            target = resolved

    is_alive = ping_host(target)
    return {"alive": is_alive, "target": target}

@router.get("/check_cache")
async def check_cache_endpoint(target: str, type: str, _=Depends(require_login)):
    scan_type = type.lower()
    target_clean = normalize_target(target)
    cached_data = get_cached_scan_data(target_clean, scan_type)
    return {"exists": cached_data is not None}

@router.get("/scan")
async def master_scan(target: str, type: str, target_type: str = "website", _=Depends(require_login)):
    if not VALID_TARGET_RE.match(target.replace("https://", "").replace("http://", "").split("/")[0]):
        return {"error": "Invalid target"}
    target = normalize_target(target, target_type)
    scan_type = type.lower()
    
    # Check for cached data FIRST 
    cached_data = get_cached_scan_data(target, scan_type)
    if cached_data:
        return cached_data

    # Ping for specific scans
    ping_required_types = ["initial", "network", "website", "webanalysis", "web analysis", "sub domain", "subdomain", "all", "udp", "full udp", "web server", "email"]
    should_ping = any(x in scan_type for x in ping_required_types)
    
    if should_ping:
        if not ping_host(target):
            return {"error": "Host not Reachable"}
    
    try:
        scan_type = get_canonical_type(scan_type)

        # Initial Identification (Tool: Whois, GeoIPLookup, TheHarvester) (file name: initial_logic.py)
        if "initial" in scan_type:
            results = initial_logic.run_initial_scan(target)
        # Subdomain Enumeration (Tool: Amass) (file name: subdomain_logic.py)
        elif "subdomain" in scan_type:
            results = subdomain_logic.run_subdomain_scan(target)
        # Web Hub Scan (Tool: Waybackmachine Wappalyzer) (file name: webhub_logic.py)
        elif "webhub" in scan_type:
            results = webhub_logic.run_webhub_scan(target)
        # Search Engine Scan (Tool: GoogleDork) (file name: search_logic.py)
        elif "search" in scan_type:
            results = search_logic.run_search_engine_scan(target)
        # User Email & Discovery (Tool: TheHarvester) (file name: email_logic.py)
        elif "email" in scan_type:
            results = email_logic.run_email_user_scan(target)
        # Network Scan (Tool: NMAP) (file name: network_logic.py)
        elif "network" in scan_type:
            results = network_logic.run_network_scan(target)
        # Web Analysis & Security (Tool: Nikto) (file name: webanalysis_logic.py)
        elif "webanalysis" in scan_type:
            results = webanalysis_logic.run_webanalysis_scan(target)
        # UDP Port Scan (Tool: NMAP) (file name: udp_logic.py)
        elif "udp" in scan_type:
            results = udp_logic.run_udp_scan(target)
        # All Scans 
        elif "all" in scan_type:
            results = {}
            
            # Sub-scans use standardized filenames naturally now
            scans_to_run = {
                "initial": initial_logic.run_initial_scan,
                "subdomain": subdomain_logic.run_subdomain_scan,
                "webhub": webhub_logic.run_webhub_scan,
                "search": search_logic.run_search_engine_scan,
                "email": email_logic.run_email_user_scan,
                "network": network_logic.run_network_scan,
                "udp": udp_logic.run_udp_scan,
                "webanalysis": webanalysis_logic.run_webanalysis_scan
            }
            
            for sub_scan_type, run_func in scans_to_run.items():
                print(f"[*] 'All' Scan: Checking cache for {sub_scan_type}...")
                cached_sub = get_cached_scan_data(target, sub_scan_type)
                if cached_sub:
                    print(f"[+] Loaded {sub_scan_type} from cache.")
                    results.update(cached_sub)
                else:
                    print(f"[-] No cache found. Executing {sub_scan_type} scan...")
                    results.update(run_func(target))
        else:
            return {"error": "Invalid scan type provided."}
    except Exception as e:
        return {"error": f"Scan failed due to an internal error: {str(e)}"}

    # Save results to JSON
    save_scan_data(target, scan_type, results)
    
    print("scan completed")
    return results


def save_scan_data(target, scan_type, results):
    try:
        if not os.path.exists(SCAN_DATA_DIR):
            os.makedirs(SCAN_DATA_DIR)
        
        # Use canonical scan type for filename consistency
        scan_type = get_canonical_type(scan_type)
        safe_target = re.sub(r'[^\w\.-]', '_', target)
        
        if scan_type == "all":
             filename = f"allscan_{safe_target}.json"
        else:
             filename = f"{scan_type}_{safe_target}.json"
             
        filepath = os.path.join(SCAN_DATA_DIR, filename)
        
        now = datetime.datetime.now()
        date_str = now.strftime("%Y-%m-%d")
        time_str = now.strftime("%H:%M:%S")

        data_to_save = {
            "metadata": {
                "date": date_str,
                "time": time_str,
                "scan_type": scan_type,
                "target": target
            },
            "results": results
        }

        with open(filepath, 'w') as f:
            json.dump(data_to_save, f, indent=4)
        cleanup_old_scans()
    except Exception as e:
        logger.warning("save_scan_data failed for %s/%s: %s", target, scan_type, e)


def get_cached_scan_data(target, scan_type):
    try:
        # Use canonical scan type for filename consistency
        scan_type = get_canonical_type(scan_type)
        safe_target = re.sub(r'[^\w\.-]', '_', target)
        
        if scan_type == "all":
             filename = f"allscan_{safe_target}.json"
        else:
             filename = f"{scan_type}_{safe_target}.json"
             
        filepath = os.path.join(SCAN_DATA_DIR, filename)

        if os.path.exists(filepath):
                # Check file age
            file_mod_time = datetime.datetime.fromtimestamp(os.path.getmtime(filepath))
            if (datetime.datetime.now() - file_mod_time).days < 5:
                with open(filepath, 'r') as f:
                    cached_json = json.load(f)
                    return cached_json.get("results")
            else:
                os.remove(filepath)
    except Exception as e:
        logger.warning("get_cached_scan_data failed for %s/%s: %s", target, scan_type, e)
    return None


def cleanup_old_scans():
    # Deletes scan files older than 5 days.
    try:
        if not os.path.exists(SCAN_DATA_DIR):
            return
            
        for filename in os.listdir(SCAN_DATA_DIR):
            filepath = os.path.join(SCAN_DATA_DIR, filename)
            if os.path.isfile(filepath) and filename.endswith(".json"):
                file_mod_time = datetime.datetime.fromtimestamp(os.path.getmtime(filepath))
                if (datetime.datetime.now() - file_mod_time).days >= 5:
                    os.remove(filepath)
    except Exception as e:
        logger.warning("cleanup_old_scans error: %s", e)


def ping_host(target):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', target]
    try:
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except subprocess.CalledProcessError:
        return False


