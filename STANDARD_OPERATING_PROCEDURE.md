# Standard Operating Procedure (SOP)

## 1. Purpose
The primary purpose of this Standard Operating Procedure (SOP) is to provide comprehensive, step-by-step instructions for the setup, execution, and monitoring of the Automated Reconnaissance Bot. This centralized platform functions as a unified security analysis framework, meticulously designed to bridge multiple industry-standard cybersecurity utilities into a single, cohesive web application. Its goal is to allow security analysts and operators to execute seamless, repetitive, and reliable web reconnaissance, penetration testing footprinting, and automated vulnerability assessments from an accessible dashboard.

## 2. Scope
This document delineates the operational boundaries for the Automated Reconnaissance Bot. It comprehensively details environmental prerequisites, Python dependency installation maps, precise file system layout, correct application initialization protocols, and proactive monitoring mechanisms during active target assessments. This SOP is the authoritative guide for administrators configuring the host server and security engineers utilizing the tool against live networks.

## 3. System Overview
### 3.1 What the Script Does
The platform operates as an orchestration layer, invoking various command-line capabilities and Python libraries dynamically to conduct a full spectrum of target reconnaissance:
- **Initial Identification:** Establishes the target's baseline. It retrieves domain registration metadata via Whois, physical server geography using GeoIP Lookup, detects HTTP Strict Transport Security (HSTS) strength in header responses through Shodan, and initiates open-source intelligence gathering for employee emails using TheHarvester.
- **Reconnaissance & Enumeration:** Expands the attack surface mapping. It uses Amass for robust subdomain footprinting, WaybackMachine APIs to parse historical snapshots for exposed or forgotten endpoints, Wappalyzer to aggressively detect underlying Content Management Systems (CMS), web frameworks, and server architectures, and automates Google Dorking to scrape search engines for exposed sensitive directories.
- **Network & Infrastructure Scanning:** Handles deep layer targeting. Utilizing the `nmap` engine, it conducts exhaustive TCP and UDP port enumerations, assesses running service versions, evaluates TLS/SSL certificates, and immediately cross-references detected service states against the National Vulnerability Database (NVD) to identify active Common Vulnerabilities and Exposures (CVEs).
- **Web Analysis:** Automates direct server interaction. It initializes local Perl-based Nikto scripts to forcefully probe web servers for thousands of known misconfigurations, dangerous default files, and severely outdated server software stacks.

### 3.2 Script Files
The ecosystem is strongly modularized. The architecture is defined by the following files:
- **UI & Gateway:**
  - `login_app/app.py`: The paramount entry point. It manages FastAPIs application states, HTTP session cookies, serves static frontend templates (`HTML/CSS/JS`), and authenticates user traffic against internal databases before mounting the primary API router.
  - `templates/`: Directory containing the frontend HTML layouts for the UI.
- **Traffic Routing:**
  - `main.py`: The backend orchestrator. It receives all REST API scan parameters (`target`, `scan_type`), executes preliminary ICMP Ping sweeps to prevent wasting resources on dead hosts, manages the response cache layer, and asynchronously delegates logic to corresponding modules.
- **Security Logic Modules:** 
  - `initial_logic.py`: Manages initial footprinting by pooling data from `whois_scanner.py`, `geoiplookup.py`, `shodan_tool.py`, and `theharvester.py`.
  - `network_logic.py` & `udp_logic.py`: Governs specialized python-nmap integrations for TCP/CVE and UDP mapping.
  - `subdomain_logic.py`: Conducts subdomain brute forcing or Certificate Transparency verification.
  - `webhub_logic.py`: A wrapper combining output from `wappalyzer_scan.py` and `waybackmachine.py`.
  - `webanalysis_logic.py`: Responsible for initializing and parsing `nikto-master/program/nikto.pl` outputs.
  - `email_logic.py` & `search_logic.py`: Isolates Google Dork generation and deep email scraping utilities.
- **Data Persistence:**
  - `login_app/users.db`: An SQLite 3 database enforcing access control. Users and their SHA-256 hashed passwords are uniquely generated via the `login_app/add_user.py` script.

### 3.3 Output Files
Data aggregation occurs consistently without manual intervention:
- **`scan_data/` Directory:** Upon the successful completion of any module (Network, Initial, Web Analysis, etc.), `main.py` aggressively logs the structured result. Files are named utilizing a standardized taxonomy (e.g., `<sanitized_target_name>_<scan_type>.json`). 
- **Caching Function:** These `.json` files function as the system cache. If an operator requests a scan for a target and module that already exists in this folder and is less than 5 days old, `main.py` immediately supplies the JSON contents to the frontend, bypassing active scans and drastically reducing operational latency.

## 4. Pre-Requisites
### 4.1 System Requirements
To safely and effectively deploy the Bot, the underlying operating system must provide specific capabilities:
- **Python Framework:** Python 3.8+ must be installed and dynamically mapped to the system's global `PATH`.
- **Nmap Engine:** Ensure the Nmap security scanner executable (for Windows or Linux) is installed and available in the environment variables; the python-nmap package strictly acts as a wrapper around the host's native Nmap.
- **Perl Interpreter:** A functional Perl implementation (e.g., Strawberry Perl for Windows) is mandatorily required for the platform to execute Nikto scripts.
- **Network Permissions:** The host system must allow outbound ICMP (Ping) packets and must not heavily throttle outgoing concurrent TCP/UDP sequence streams.

### 4.2 Python Package Dependencies
The execution hinges on a curated list of PyPI packages. They handle server operations, web scraping, API calls, and OS bindings. The mandatory packages include, but are not limited to:
- **Server/Web Routing:** `fastapi`, `uvicorn`, `pydantic`, `jinja2`, `python-multipart`, `starlette`
- **Data Acquisition/Parsing:** `requests`, `beautifulsoup4`, `dnspython`, `ipwhois`
- **Security Specific:** `python-nmap` (wrapper), `nvdlib` (CVE parsing), `python-Wappalyzer`
- **Utility:** `setuptools==70.0.0` (required for specific backward compatibility in some enumeration libraries).
*(Note: A `requirements.txt` file exists in the directory that matches these specific dependencies).*

## 5. Initial Setup Procedure
### 5.1 File Structure
Before initialization, physically verify the integrity of the project directories to prevent runtime `ModuleNotFound` exceptions:
1. Ensure the root directory (e.g., `Automated-Reconnaissance-Bot/`) strictly contains `main.py` and all scanning scripts (`initial_logic.py`, `network_logic.py`, `theharvester.py`, etc.).
2. Validate the presence of the `nikto-master/` directory which houses the Perl executable codebase.
3. Validate the structural presence of `login_app/`, explicitly containing `app.py` and `users.db`.
4. Ensure the existence of `templates/` to avoid Jinja2 rendering issues.
5. If the `scan_data/` directory does not organically exist, create it manually or ensure the application possesses Read/Write OS permissions to dynamically formulate it in the root folder.

### 5.2 Install Python Packages
To properly stage the operational environment, dependencies must be fully installed. 
1. Open a system terminal/command prompt.
2. Ensure you are situated within the `Automated-Reconnaissance-Bot` project directory.
3. Execute the batch pip installation process:
   ```bash
   pip install -r requirements.txt
   # OR use the direct command:
   # pip install fastapi uvicorn pydantic jinja2 python-multipart starlette requests beautifulsoup4 python-nmap nvdlib dnspython ipwhois python-Wappalyzer setuptools==70.0.0
   ```
4. Verify no red "failed to build wheel" or missing C++ compiler errors persist during the `python-nmap` or `psutil` compilations within pip.

## 6. Running the Script
Bootstrapping the environment correctly is the most critical operational step. Direct initialization of backend modules will result in immediate authentication failures.
1. Initiate the command prompt as an Administrator (or root via `sudo` on Linux) to guarantee that deep TCP syntaxes (like Nmap stealth scans) execute without permission denials.
2. Traverse to the top-level directory (`Automated-Reconnaissance-Bot/`).
3. Deploy the application stack through the authentication router:
   ```bash
   python login_app/app.py
   ```
   **CRITICAL REMINDER:** Do NOT execute `python main.py`. Doing so bypasses all FastAPIs session management and strips the frontend of its capabilities.
4. Watch the console. Successful instantiation is indicated when the terminal returns: 
   `[*] Starting Login Application on Port 8000...` and Uvicorn log statements.
5. Open an internet browser and navigate to: **http://127.0.0.1:8000**
6. Authenticate utilizing the internal database credentials to access the central dashboard. **Note: As there are no default or hardcoded credentials, you must formulate your first user profile before attempting login:**
   - Open a secondary terminal and navigate to the `login_app/` directory.
   - Execute: `python add_user.py`
   - Follow the interactive prompts to securely convert your preferred Username and Password into a SHA-256 hash and inject it into the SQLite database.
   - Utilize these newly minted credentials to successfully log into the web interface.

## 7. Monitoring the Run
Once target assessments are queued from the dashboard, backend operational awareness is critical:
- **Terminal Log Streams:** Keep the Uvicorn terminal visible. It acts as the primary debugger. It will live-stream API REST accesses (`GET /scan?target=...`), document the status of pre-scan ICMP Ping sweeps, record module hand-offs, and visibly display standard Python exception `Tracebacks` and HTTP 500 errors if an underlying API fails or if an OS tool (Nmap/Perl) is unexpectedly absent from the PATH.
- **Cache Yield Monitoring:** As scanning engines conclude their lengthy routines (Nikto and Nmap can run for several minutes), operators can structurally verify progress by monitoring the `scan_data/` directory. The appearance of newly generated JSON structures (e.g., `example_com_initial.json`) physically confirms a completed thread.
- **Stale Scan Flush Procedure:** Should a scan freeze indefinitely, or should an operator require a live pull regardless of the 5-day freshness rule, simply navigate into `scan_data/` and permanently delete the specific `.json` file associated with the target and scan type, then re-execute the request from the web dashboard.