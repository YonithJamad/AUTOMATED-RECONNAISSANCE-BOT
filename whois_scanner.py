# Yonith Tool Whois

import socket
import re
from ipwhois import IPWhois

def get_whois_details(user_input):
    target = re.sub(r'^https?://', '', user_input)
    target = re.sub(r'^www\.', '', target).split('/')[0]

    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    
    try:
        if re.match(ip_pattern, target):
            ip_address = target
        else:
            ip_address = socket.gethostbyname(target)

        obj = IPWhois(ip_address)
        results = obj.lookup_rdap(depth=1)
        
        net = results.get('network', {})
        
        return {
            "asn": results.get('asn'),
            "asn_description": results.get('asn_description'),
            "asn_country": results.get('asn_country_code'),
            "network_name": net.get('name'),
            "ip_range": net.get('cidr'),
            "registry": results.get('asn_registry', '').upper()
        }

    except socket.gaierror:
        return {"error": f"Could not resolve '{target}'"}
    except Exception as e:
        return {"error": str(e)}

def run_once():
    user_input = input("Enter Website URL or IP Address: ").strip()
    if not user_input:
        print("[!] No input provided. Exiting.")
        return

    result = get_whois_details(user_input)

    print(f"      DETAILS FOR: {user_input}")
    
    print(f"ASN:              {result.get('asn')}")
    print(f"ASN Description:  {result.get('asn_description')}")
    print(f"ASN Country:      {result.get('asn_country')}")
    
    print(f"Network Name:     {result.get('network_name')}")
    print(f"IP Range (CIDR):  {result.get('ip_range')}")
    print(f"Registry:         {result.get('registry')}")

if __name__ == "__main__":
    run_once()
