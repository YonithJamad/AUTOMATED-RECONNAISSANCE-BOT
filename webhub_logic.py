# Connects to 2 files (waybackmachine.py, wappalyzer.py) with the logic of the webhub scan

import waybackmachine
import wappalyzer_scan as wappalyzer

def run_webhub_scan(target):
    final_web_hub_data = {}

    # Wayback Machine Scan
    wayback_data = waybackmachine.get_wayback_data(target)
    if wayback_data and "web_hub" in wayback_data:
        final_web_hub_data.update(wayback_data["web_hub"])

    # Wappalyzer Scan
    wappalyzer_data = wappalyzer.get_wappalyzer_data(target)
    if wappalyzer_data and "web_hub" in wappalyzer_data:
        final_web_hub_data.update(wappalyzer_data["web_hub"])

    return {"web_hub": final_web_hub_data}