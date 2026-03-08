# Yonith Tool GeoIP Lookup
import requests

def get_geo_info(target):
    target = target.replace("https://", "").replace("http://", "").split('/')[0]
    
    url = f"http://ip-api.com/json/{target}"
    
    try:
        response = requests.get(url, timeout=10)
        data = response.json()
        
        if data.get("status") == "success":
            return {
                "IP": data.get("query"),
                "Country": data.get("country"),
                "City": data.get("city")
            }
        else:
            return None
            
    except Exception as e:
        # print(f"Connection Error: {e}")
        return None

if __name__ == "__main__":
    user_input = input("Enter IP Address or Website: ").strip()
    
    if user_input:
        result = get_geo_info(user_input)
        
        if result:            
            print(f"Country:     {result['Country']}")
            print(f"City:        {result['City']}")
        else:
            print("Could not fetch details. Please check the address or your internet connection.")