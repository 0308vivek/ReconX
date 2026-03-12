import sys
import json
import socket
import ssl
from datetime import datetime

def check_ssl(domain):
    result = {
        "issuer": None, 
        "subject": None, 
        "valid_from": None, 
        "valid_to": None,
        "tls_version": None,
        "expired": False,
        "error": None
    }
    
    port = 443
    context = ssl.create_default_context()
    # Allowing self-signed or invalid certs to get their info
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        with socket.create_connection((domain, port), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                
                # To easily parse human readable details we would normally use ssl.get_peercert() with check_hostname=True
                # But since we want to be robust, we reconnect with default validation
                ssock_info = ssock.version()
                result["tls_version"] = ssock_info
                
    except Exception:
        # If it fails, we fall back to the error block
        pass
        
    # Reconnecting properly to get the mapped cert info if valid
    try:
        context_strict = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=3) as sock:
            with context_strict.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Parse issuer
                issuer_dict = {}
                for item in cert.get('issuer', []):
                    for k, v in item:
                        issuer_dict[k] = v
                result["issuer"] = issuer_dict.get('organizationName', issuer_dict.get('commonName', 'Unknown'))
                
                # Parse Dates
                not_before = cert.get('notBefore')
                not_after = cert.get('notAfter')
                
                if not_before:
                    date_before = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
                    result["valid_from"] = date_before.strftime('%Y-%m-%d')
                    
                if not_after:
                    date_after = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    result["valid_to"] = date_after.strftime('%Y-%m-%d')
                    
                    if datetime.utcnow() > date_after:
                        result["expired"] = True
                        
    except ssl.SSLCertVerificationError as e:
        result["expired"] = True
        result["error"] = f"SSL Verification Error: {str(e)}"
    except socket.gaierror:
        result["error"] = "DNS Resolution failed."
    except socket.timeout:
        result["error"] = "Connection to port 443 timed out."
    except ConnectionRefusedError:
        result["error"] = "Connection refused on port 443."
    except Exception as e:
        result["error"] = str(e)
        
    return json.dumps(result)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        domain = sys.argv[1]
        print(check_ssl(domain))
    else:
        print(json.dumps({"error": "No domain provided"}))
