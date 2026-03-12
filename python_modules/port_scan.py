import sys
import json
import socket
import concurrent.futures

def scan_port(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.5)
    result = sock.connect_ex((host, port))
    sock.close()
    if result == 0:
        return port
    return None

def scan_ports(domain):
    ports_to_scan = [21, 22, 80, 443, 3306]
    result = {"open_ports": [], "error": None}
    
    try:
        host = socket.gethostbyname(domain)
        open_ports = []
        
        # Concurrently scan the target ports
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(scan_port, host, port) for port in ports_to_scan]
            for future in concurrent.futures.as_completed(futures):
                port = future.result()
                if port is not None:
                    open_ports.append(port)
                    
        result["open_ports"] = sorted(open_ports)
        
    except socket.gaierror:
        result["error"] = "Invalid domain or DNS resolution failed."
    except Exception as e:
        result["error"] = str(e)
        
    return json.dumps(result)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        domain = sys.argv[1]
        print(scan_ports(domain))
    else:
        print(json.dumps({"error": "No domain provided"}))
