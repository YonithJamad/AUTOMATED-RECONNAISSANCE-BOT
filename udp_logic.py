# Yonith Tool NMAP 

import nmap
import re

def get_udp_host_info(host_data, user_input):
    ip_address = host_data.get('addresses', {}).get('ipv4', user_input)
    
    hostnames = host_data.get('hostnames', [])
    rdns_name = "No domain found"
    if hostnames:
        for h in hostnames:
            if h.get('name'):
                rdns_name = h['name']
                break

    return {
        "ip": ip_address,
        "rdns": rdns_name
    }

def get_udp_ports(host_data):
    open_ports = []
    
    if 'udp' in host_data.all_protocols():
        lport = sorted(host_data['udp'].keys())
        for port in lport:
            port_info = host_data['udp'][port]
            state = port_info['state']
            if "open" in state:
                service = port_info.get('name', 'unknown')
                product = port_info.get('product', '')
                version = port_info.get('version', '')
                extrainfo = port_info.get('extrainfo', '')
                full_version = f"{product} {version} {extrainfo}".strip()
                
                open_ports.append({
                    "port": port,
                    "protocol": "udp",
                    "state": state,
                    "service": service,
                    "version": full_version
                })
    return open_ports

def run_udp_scan(target):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments='-sU -Pn -p 0-65535 -T4 --min-rate 1000 --max-retries 1')
    except Exception as e:
        return {"error": str(e)}
    host = target
    if host not in nm.all_hosts():
        if len(nm.all_hosts()) > 0:
            host = nm.all_hosts()[0]
        else:
            return {"error": "Host not found or down during UDP scan"}

    host_data = nm[host]
    
    return {
        "udp_scan": {
            "target_info": get_udp_host_info(host_data, target),
            "open_ports": get_udp_ports(host_data)
        }
    }

def full_udp_scan():
    raw_input = input("Enter Website URL or IP Address: ").strip()
    target = re.sub(r'^https?://', '', raw_input).split('/')[0]
    
    print(f"\n[!] Starting full UDP scan on {target}...")
    print("[!] This will take a significant amount of time. Please wait...")
    
    result = run_udp_scan(target)
    
    if "error" in result:
        print(f"Error occurred: {result['error']}")
        print("Note: Ensure you are running as Root/Administrator.")
        return
        
    udp_scan = result.get("udp_scan", {})
    open_ports = udp_scan.get("open_ports", [])
    
    print(f"\nDiscovered {len(open_ports)} UDP ports:")
    if len(open_ports) > 0:
        print(f"{'PORT':<10} {'STATE':<15} {'SERVICE':<15}")
        print("-" * 40)
        for p in open_ports:
            print(f"{p['port']:<10} {p['state']:<15} {p['service']:<15}")
    else:
        ip_address = udp_scan.get("target_info", {}).get("ip", target)
        print(f"All 65536 scanned ports on {target} ({ip_address}) are in ignored states.")

if __name__ == "__main__":
    full_udp_scan()