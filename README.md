# Automated Reconnaissance Bot

This project is a powerful, integrated security analysis and scanning platform designed to simplify web reconnaissance and vulnerability assessments. By bridging multiple industry-standard security tools into a single, unified web interface, it provides seamless scanning, data management, and actionable insights.

The platform comprises an authentication system and a central dashboard where users can execute targeted scans, aggregate results, and view formatted intelligence.

## 🛠️ Security Tools & Integrations

The platform orchestrates the following security tools to perform comprehensive reconnaissance across different vectors:

*   **Initial Identification:**
    *   **Whois:** Domain registration and ownership details.
    *   **GeoIPLookup:** Geolocation tracking for target IPs.
    *   **Shodan:** Checks for HTTP Strict Transport Security (HSTS) presence and strength.
    *   **TheHarvester:** Open-source intelligence gathering for emails, subdomains, and names.
*   **Reconnaissance & Enumeration:**
    *   **Amass:** In-depth subdomain enumeration and network mapping.
    *   **WaybackMachine:** Historical archive snapshots of targeted web pages.
    *   **Wappalyzer:** Identifying underlying technologies, frameworks, and CMS used by the target.
    *   **Google Dorks:** Advanced search engine queries for exposed files and vulnerable endpoints.
*   **Network & Infrastructure Scanning:**
    *   **Nmap (TCP & UDP):** Comprehensive port scanning, service version detection, and network analysis.
*   **Web Analysis & Vulnerability Scanning:**
    *   **Nikto:** Web server scanner for identifying dangerous files, outdated server software, and misconfigurations.

## 1. How to Execute the Project

### The Entry Point
The main entry point for this application is **`login_app/app.py`**. 
You should **NOT** run `main.py` directly to start the web server.

### Execution Steps
1. Open your terminal or command prompt.
2. Navigate to the root of the project folder.
3. Run the following command:
   ```bash
   python login_app/app.py
   ```
4. The terminal will display `[*] Starting Login Application on Port 8000...` and start the Uvicorn server.
5. Open your web browser and go to: **[http://127.0.0.1:8000](http://127.0.0.1:8000)**
6. You will be greeted by the Login Page.

---

## 2. Managing User Credentials

For security purposes, there are no default or hardcoded credentials. Passwords are securely hashed using the **SHA-256 algorithm**. To access the dashboard, you must create a user in your local database (`login_app/users.db`).

We have provided a utility script to securely add users via the terminal.

### Adding a new user
1. Navigate to the `login_app` directory.
2. Run the `add_user.py` script:
   ```bash
   python add_user.py
   ```
3. You will be prompted to securely type a new username and password.

*(Alternatively, you can provide the username in line: `python add_user.py -u myusername`)*

---

## 3. Required Modules to Download

Before running the project, you must install the required Python libraries. You can install all of them at once using `pip`.

Run this command in your terminal:
```bash
pip install fastapi uvicorn pydantic jinja2 python-multipart starlette requests beautifulsoup4 python-nmap nvdlib dnspython ipwhois python-Wappalyzer setuptools==70.0.0 itsdangerous 
```

### OS-Level Dependencies
Because this bot utilizes underlying operating system commands for comprehensive scanning, ensure the following are installed and added to your system's PATH:
- **[Nmap](https://nmap.org/download.html)**: Only the Nmap Python module is required for `network_logic.py` and `udp_logic.py`.
- **[Perl](https://strawberryperl.com/)**: Required to run Nikto in `webanalysis_logic.py`.
- **Ping**: Native to Windows/Linux/macOS (used to check host physical reachability).

---

## 4. Flow of the Files

The project is structured into Authentication, API Routing, and Modular Scanning Logic.

### A. Authentication & UI (`login_app/app.py`)
- **`login_app/app.py`** is the outer shell. It initializes the FastAPI application, mounts the HTML templates and static assets (CSS/JS) directly from the `templates/` directories, and manages session cookies.
- It connects to a local SQLite database (`login_app/users.db`) to verify user credentials.
- Once authenticated, it forwards the user to the `/dashboard`.
- It crucially **imports the router from `main.py`** (`from main import router as scan_router`) to handle all scanning endpoints under the same port.

### B. Core Router & Cache Manager (`main.py`)
- **`main.py`** acts as the Traffic Controller. It receives API requests from the dashboard (e.g., `/scan?target=example.com&type=network`).
- **Caching Mechanism**: Before triggering a scan, it checks the `scan_data/` folder to see if a recent JSON file exists for the target. If it does (and is less than 5 days old), it instantly returns the cached data.
- **Ping Check**: If the target is not cached, `main.py` attempts to `ping` the host to ensure it is alive before wasting time on deep scans.
- If the host is alive, `main.py` delegates the task to the appropriate `_logic.py` module.

### C. The Modular Scanning Logic (`*_logic.py`)
Each file handles a specific type of reconnaissance. `main.py` calls them dynamically based on the requested scan type:

1. **`initial_logic.py`**: Gathers preliminary footprinting data. It delegates further to:
   - `whois_scanner.py`: Fetches domain registration details.
   - `geoiplookup.py`: Determines the geographical location of the IP.
   - `shodan_tool.py`: Queries Shodan for exposed ports and metadata.
   - `theharvester.py`: Scrapes search engines for emails and subdomains.

2. **`network_logic.py`**: Uses Python-Nmap (`nmap`) to perform deep TCP port scanning, service version detection, SSL certificate parsing, and references `nvdlib` to cross-check found services for CVEs (Vulnerabilities).

3. **`udp_logic.py`**: Performs UDP port scanning using Nmap to find services like DNS, SNMP, or NTP that might be exposed.

4. **`subdomain_logic.py`**: Enumerates subdomains using SSL Certificate Transparency logs (crt.sh) and checks for active wildcard DNS and Subdomain Takeover vulnerabilities.

5. **`webanalysis_logic.py`**: Executes the local Nikto installation (`nikto-master/program/nikto.pl` via Perl script) to deeply examine the web server for misconfigurations and outdated software.

6. **`webhub_logic.py`**: Aggregates web infrastructure details by calling:
   - `wappalyzer_scan.py`: Identifies technologies (CMS, JS frameworks) running on the site.
   - `waybackmachine.py`: Fetches historical URLs and endpoints from the Internet Archive.

7. **`search_logic.py`**: Automates Google Dorking to find exposed files, directories, or login pages indexed by Google.

8. **`email_logic.py`**: Uses `theharvester.py` to compile a list of employees or related email addresses for the target domain.

### D. Data Storage
- **`scan_data/`**: Directory where `main.py` saves the output of every completed scan as a JSON file (e.g., `example_com_network.json`). This prevents duplicate scanning.
- **`login_app/users.db`**: Stores structured username and password relationships. Standard SQLite 3 structure.