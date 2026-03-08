# Yonith Tool Whois

import socket
import re
from ipwhois import IPWhois

def get_whois_details(user_input):
    # Clean the input (remove https:// or www. if the user pasted them)
    target = re.sub(r'^https?://', '', user_input)
    target = re.sub(r'^www\.', '', target).split('/')[0]

    # 2. Determine if it's an IP or a Domain
    ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    
    try:
        if re.match(ip_pattern, target):
            ip_address = target
        else:
            # print(f"[*] Resolving domain '{target}' to IP...")
            ip_address = socket.gethostbyname(target)
            # print(f"[*] IP Found: {ip_address}")

        # 3. Fetch Infrastructure (ASN & IP) Details
        # print(f"[*] Fetching ASN & Network data...")
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
        # print(f"[!] Error: Could not resolve '{target}'. Check the URL and your connection.")
        return {"error": f"Could not resolve '{target}'"}
    except Exception as e:
        # print(f"[!] Error during lookup: {str(e)}")
        return {"error": str(e)}

def run_once():
    # 1. Ask for input once
    user_input = input("Enter Website URL or IP Address: ").strip()
    if not user_input:
        print("[!] No input provided. Exiting.")
        return

    result = get_whois_details(user_input)

    print("\n" + "="*45)
    print(f"      DETAILS FOR: {user_input}")
    print("="*45)
    
    # Specific ASN and IP details you requested
    print(f"ASN:              {result.get('asn')}")
    print(f"ASN Description:  {result.get('asn_description')}")
    print(f"ASN Country:      {result.get('asn_country')}")
    
    print(f"\nNetwork Name:     {result.get('network_name')}")
    print(f"IP Range (CIDR):  {result.get('ip_range')}")
    print(f"Registry:         {result.get('registry')}")
    print("="*45)

if __name__ == "__main__":
    run_once()
