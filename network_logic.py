# Yonith Tool NMAP 

import nmap
import socket
import re
import sys
import nvdlib
import time

def get_host_info(host_data, user_input):
    # Extract IP
    ip_address = host_data.get('addresses', {}).get('ipv4', user_input)
    
    # Extract Hostname/Reverse DNS
    hostnames = host_data.get('hostnames', [])
    rdns_name = "No domain found"
    if hostnames:
        for h in hostnames:
            if h.get('name'):
                rdns_name = h['name']
                break

    # Extract Website Name from SSL Common Name (CN)
    website_name = "Unknown Website"
    for proto in host_data.all_protocols():
        for port in host_data[proto]:
            if 'script' in host_data[proto][port]:
                script_out = host_data[proto][port]['script']
                if 'ssl-cert' in script_out:
                    output = script_out['ssl-cert']
                    match = re.search(r"commonName=([a-zA-Z0-9.-]*)", output)
                    if match:
                        website_name = match.group(1)
                        website_name = website_name.replace('*.', '')
                        break
        if website_name != "Unknown Website":
            break

    return {
        "ip": ip_address,
        "rdns": rdns_name,
        "website_name": website_name
    }

def get_ports(host_data):
    open_ports = []
    
    for proto in host_data.all_protocols():
        lport = sorted(host_data[proto].keys())
        for port in lport:
            port_info = host_data[proto][port]
            state = port_info['state']
            if state == 'open':
                service = port_info.get('name', 'unknown')
                product = port_info.get('product', '')
                version = port_info.get('version', '')
                extrainfo = port_info.get('extrainfo', '')
                full_version = f"{product} {version} {extrainfo}".strip()
                
                open_ports.append({
                    "port": port,
                    "protocol": proto,
                    "service": service,
                    "version": full_version
                })
    return open_ports

def get_ssl_details(host_data):
    ssl_details = []
    for proto in host_data.all_protocols():
        for port in host_data[proto]:
            if 'script' in host_data[proto][port]:
                script_out = host_data[proto][port]['script']
                if 'ssl-cert' in script_out:
                    output = script_out['ssl-cert']
                    # Improved regex to handle various formatting in nmap output
                    subject = re.search(r"Subject:\s*(.*)", output, re.I)
                    issuer = re.search(r"Issuer:\s*(.*)", output, re.I)
                    not_valid_before = re.search(r"Not valid before:\s*(.*)", output, re.I)
                    not_valid_after = re.search(r"Not valid after:\s*(.*)", output, re.I)
                    
                    ssl_details.append({
                        "port": f"{port}/{proto}",
                        "subject": subject.group(1).strip() if subject else 'N/A',
                        "issuer": issuer.group(1).strip() if issuer else 'N/A',
                        "validity_start": not_valid_before.group(1).strip() if not_valid_before else 'N/A',
                        "validity_end": not_valid_after.group(1).strip() if not_valid_after else 'N/A'
                    })
    return ssl_details

def get_cvss_details(cve_id):
    try:
        time.sleep(0.1) 
        r = nvdlib.searchCVE(cveId=cve_id)
        if r:
            cve = r[0]
            score = None
            if hasattr(cve, 'metrics') and cve.metrics:
                if hasattr(cve.metrics, 'cvssMetricV31'):
                    score = cve.metrics.cvssMetricV31[0].cvssData.baseScore
                elif hasattr(cve.metrics, 'cvssMetricV30'):
                    score = cve.metrics.cvssMetricV30[0].cvssData.baseScore
                elif hasattr(cve.metrics, 'cvssMetricV2'):
                    score = cve.metrics.cvssMetricV2[0].cvssData.baseScore
            
            if score is not None:
                return score
    except Exception as e:
        # print(f"[-] Error fetching {cve_id} from NVD: {e}")
        pass
    return None

def get_severity_info(score):
    s = float(score)
    if s == 0.0:
        return "None", "Grey", "#9E9E9E"
    elif 0.1 <= s <= 3.9:
        return "Low", "Green", "#4CAF50"
    elif 4.0 <= s <= 6.9:
        return "Medium", "Yellow / Amber", "#FFC107"
    elif 7.0 <= s <= 8.9:
        return "High", "Orange", "#FF9800"
    elif 9.0 <= s <= 10.0:
        return "Critical", "Red", "#F44336"
    return "Unknown", "Grey", "#9E9E9E"

def get_cves(host_data):
    cve_cvss_pattern = r"(CVE-\d{4}-\d{4,7})\s+(\d+\.\d)"
    found_vulnerabilities = []

    for proto in host_data.all_protocols():
        for port in host_data[proto]:
            if 'script' in host_data[proto][port]:
                script_out = host_data[proto][port]['script']
                if 'vulners' in script_out:
                    output = script_out['vulners']
                    matches = re.findall(cve_cvss_pattern, output)
                    found_vulnerabilities.extend(matches)
    
    unique_vulnerabilities = list(set(found_vulnerabilities))
    
    results = []
    for cve_id, nmap_score in unique_vulnerabilities:
        nvd_score = get_cvss_details(cve_id)
        score = nvd_score if nvd_score is not None else float(nmap_score)
        
        sev, color, hex_code = get_severity_info(score)
        
        results.append({
            "cve": cve_id,
            "score": score,
            "severity": sev,
            "recommend_color": color,
            "hex_code": hex_code
        })
    
    results.sort(key=lambda x: x['score'], reverse=True)
    return results

def run_network_scan(target):
    """
    Called by main.py
    Returns structured dictionary
    """
    nm = nmap.PortScanner()
    try:
        nm.scan(target, arguments="-p- -sT -sV -Pn --unprivileged --script vulners,ssl-cert --min-rate 5000")
    except Exception as e:
        # print(f"[-] Nmap scan execution failed: {e}")
        return {"error": f"Nmap execution error: {str(e)}"}

    host = target
    if host not in nm.all_hosts():
        if len(nm.all_hosts()) > 0:
            host = nm.all_hosts()[0]
        else:
            return {"error": "Host not found or down"}

    host_data = nm[host]
    
    return {
        "network_scan": {
            "target_info": get_host_info(host_data, target),
            "open_ports": get_ports(host_data),
            "ssl_info": get_ssl_details(host_data),
            "vulnerabilities": get_cves(host_data)
        }
    }

def print_results(results):
    if "error" in results:
        print(f"[-] Error: {results['error']}")
        return

    data = results["network_scan"]
    
    info = data["target_info"]
    print("\n" + "="*50)
    print("[+] TARGET IDENTIFICATION")
    print("="*50)
    print(f"  IP Address:    {info['ip']}")
    print(f"  Reverse DNS:   {info['rdns']}")
    print(f"  Website Found: {info['website_name']}")
    
    # Ports
    print("\n[+] OPEN PORTS & SERVICES")
    print("-" * 50)
    ports = data["open_ports"]
    if ports:
        print(f"{'PORT':<10} | {'SERVICE':<15} | {'VERSION'}")
        for p in ports:
            print(f"{str(p['port'])+'/'+p['protocol']:<10} | {p['service']:<15} | {p['version']}")
    else:
         print("No open ports found.")

    # SSL
    print("\n[+] SSL/TLS CERTIFICATE DETAILS")
    print("-" * 50)
    ssl = data["ssl_info"]
    if ssl:
        for s in ssl:
            print(f"  Port: {s['port']}")
            print(f"  Subject:  {s['subject']}")
            print(f"  Issuer:   {s['issuer']}")
            print(f"  Validity: {s['validity_start']} TO {s['validity_end']}")
            print("-" * 30)
    else:
        print("No SSL/TLS certificates found.")

    # Vulns
    print("\n[+] VULNERABILITIES DETECTED (CVE & CVSS)")
    print("-" * 50)
    vulns = data["vulnerabilities"]
    if vulns:
        print(f"{'CVE ID':<20} | {'CVSS':<6} | {'SEVERITY':<10} | {'COLOR':<15} | {'HEX'}")
        print("-" * 75)
        for v in vulns:
             print(f"{v['cve']:<20} | {v['score']:<6} | {v['severity']:<10} | {v['recommend_color']:<15} | {v['hex_code']}")
    else:
        print("No CVEs with CVSS scores detected.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Enter website or IP to scan: ")
    
    if target:
        print(f"\n[+] Running Nmap scan on {target}...")
        results = run_network_scan(target)
        print_results(results)