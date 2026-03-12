import sys
import json
import socket
import dns.resolver

def scan_dns(domain):
    result = {"ip": None, "hostname": None, "records": {}, "error": None}
    
    try:
        # Get IP address
        result["ip"] = socket.gethostbyname(domain)
        
        # Get hostname
        try:
            result["hostname"] = socket.gethostbyaddr(result["ip"])[0]
        except socket.herror:
            result["hostname"] = "Unknown"
            
        # Get DNS records
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']
        
        for qtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, qtype)
                result["records"][qtype] = [rdata.to_text() for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
                pass
                
    except socket.gaierror:
        result["error"] = "Invalid domain or failed to resolve."
    except Exception as e:
        result["error"] = str(e)
        
    return json.dumps(result)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        domain = sys.argv[1]
        print(scan_dns(domain))
    else:
        print(json.dumps({"error": "No domain provided"}))
