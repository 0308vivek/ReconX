import sys
import json
import requests
import concurrent.futures

def check_dir(url, directory):
    target_url = f"{url}{directory}"
    try:
        # Use a short timeout and no redirects to speed up scanning
        response = requests.head(target_url, timeout=3, allow_redirects=False)
        # We consider mostly 200, 301, 302, 401, 403 as "exists"
        if response.status_code in [200, 301, 302, 401, 403]:
            return directory
    except requests.exceptions.RequestException:
        pass
    return None

def scan_directories(domain):
    directories_to_scan = ['/admin', '/login', '/dashboard', '/api', '/wp-admin', '/backup', '/test']
    result = {"directories": [], "error": None}
    
    url = f"http://{domain}" if not domain.startswith("http") else domain
    
    try:
        discovered = []
        # Concurrently scan the directories
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(check_dir, url, d) for d in directories_to_scan]
            for future in concurrent.futures.as_completed(futures):
                d = future.result()
                if d is not None:
                    discovered.append(d)
                    
        result["directories"] = sorted(discovered)
        
    except Exception as e:
        result["error"] = str(e)
        
    return json.dumps(result)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        domain = sys.argv[1]
        print(scan_directories(domain))
    else:
        print(json.dumps({"error": "No domain provided"}))
