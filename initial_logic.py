# Connects to 4 files (whois.py, geoiplookup.py, theharvester.py, shodan_tool.py) with the logic of the initial scan

import whois_scanner
import geoiplookup
import hosting_detector as theharvester
import shodan_tool

def run_initial_scan(target):
    
    result = {}

    # Whois Scan (whois_scanner.py)
    whois_data = whois_scanner.get_whois_details(target)
    if whois_data:
        result.update(whois_data)

    # GeoIP Scan (geoiplookup.py)
    geo_data = geoiplookup.get_geo_info(target)
    if geo_data:
        result["country"] = geo_data.get("Country")
        result["city"] = geo_data.get("City")

    # HSTS Check (shodan_tool.py replacement)
    host, present, strength, detail = shodan_tool.check_hsts(target)
    if present is None:
        result["hsts_presence"] = f"Error - {str(detail)[:60]}"
        result["hsts_strength"] = "NONE"
        result["hsts_header"] = "---"
    elif not present:
        result["hsts_presence"] = "NO"
        result["hsts_strength"] = "NONE"
        result["hsts_header"] = "---"
    else:
        result["hsts_presence"] = "YES"
        result["hsts_strength"] = strength
        result["hsts_header"] = detail
    
    # TheHarvester Scan (theharvester.py)
    theharvester_data = theharvester.get_theharvester_data(target)
    if theharvester_data:
        result.update(theharvester_data)
        
    return {"initial_id": result}