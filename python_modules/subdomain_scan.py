import sys
import json
import requests

def scan_subdomains(domain):
    result = {"subdomains": [], "error": None}
    
    try:
        # Use crt.sh API to search for subdomains using Certificate Transparency logs
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        
        # Set a User-Agent and relatively low timeout as crt.sh can be slow
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(url, headers=headers, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            subdomains = set()
            
            for entry in data:
                name_value = entry.get("name_value", "")
                # name_value can contain multiple domains separated by newline
                for name in name_value.split('\n'):
                    name = name.strip()
                    if name.endswith(domain) and not name.startswith("*"):
                        subdomains.add(name)
            
            result["subdomains"] = sorted(list(subdomains))
        else:
            result["error"] = f"Failed to fetch data, status code: {response.status_code}"
            
    except requests.exceptions.RequestException as e:
        result["error"] = f"Request error: {str(e)}"
    except Exception as e:
        result["error"] = str(e)
        
    return json.dumps(result)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        domain = sys.argv[1]
        print(scan_subdomains(domain))
    else:
        print(json.dumps({"error": "No domain provided"}))
