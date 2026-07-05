import os
import ssl
import socket
import requests
import nmap
from datetime import datetime

# =====================================================
# FORCE NMAP PATH (Windows)
# =====================================================

NMAP_PATH = r"C:\Program Files (x86)\Nmap"
if os.path.exists(NMAP_PATH):
    os.environ["PATH"] += os.pathsep + NMAP_PATH


# =====================================================
# PORT INTELLIGENCE DATABASE
# =====================================================

PORT_INFO = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP Secure",
    993: "IMAPS",
    995: "POP3S",
    1433: "MS SQL",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "Remote Desktop",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP Alternate"
}

HIGH_RISK_PORTS = {21, 23, 135, 139, 445, 3389, 5900}


# =====================================================
# PORT SCANNING
# =====================================================

def scan_ports(target):
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments="-T4 -F")

        open_ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in sorted(nm[host][proto].keys()):
                    if nm[host][proto][port]["state"] == "open":
                        open_ports.append(port)
        return open_ports

    except Exception as e:
        print(f"NMAP ERROR: {e}")
        return []


# =====================================================
# PORT INTELLIGENCE
# =====================================================

def analyze_ports(open_ports):
    return [
        f"Port {port} ({PORT_INFO.get(port, 'Unknown Service')})"
        for port in open_ports
    ]


# =====================================================
# SSL ANALYSIS
# =====================================================

def ssl_check(target):
    results = []
    try:
        context = ssl.create_default_context()
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(5)

        with context.wrap_socket(raw_sock, server_hostname=target) as sock:
            sock.connect((target, 443))
            cert = sock.getpeercert()

        if not cert:
            results.append("Certificate Not Found")
            return results

        issuer = dict(x[0] for x in cert.get("issuer", []))
        results.append(f"Issuer: {issuer.get('organizationName', 'Unknown')}")

        not_after = cert.get("notAfter", "")
        results.append(f"Valid Until: {not_after}")

        if not_after:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            if expiry < datetime.utcnow():
                results.append("WARNING: Certificate is EXPIRED")
            elif (expiry - datetime.utcnow()).days < 30:
                results.append("WARNING: Certificate expires in under 30 days")

    except ssl.SSLCertVerificationError:
        results.append("SSL Error: Certificate verification failed")
    except ssl.SSLError as e:
        results.append(f"SSL Error: {e}")
    except Exception as e:
        results.append(f"Connection Error: {e}")

    return results


# =====================================================
# SECURITY HEADER ANALYSIS
# =====================================================

REQUIRED_HEADERS = {
    "Content-Security-Policy": "Missing Content-Security-Policy",
    "Strict-Transport-Security": "Missing HSTS",
    "X-Frame-Options": "Missing X-Frame-Options",
    "X-Content-Type-Options": "Missing X-Content-Type-Options",
    "Referrer-Policy": "Missing Referrer-Policy",
    "Permissions-Policy": "Missing Permissions-Policy"
}


def header_check(url):
    if not url.startswith("http"):
        url = f"https://{url}"

    findings = []
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        headers = response.headers
        for header, issue in REQUIRED_HEADERS.items():
            if header not in headers:
                findings.append(issue)
    except requests.exceptions.SSLError:
        findings.append("Connection Error: SSL verification failed")
    except requests.exceptions.ConnectionError:
        findings.append("Connection Error: Host unreachable")
    except Exception as e:
        findings.append(f"Connection Error: {e}")

    return findings


# =====================================================
# RISK SCORE CALCULATION
# =====================================================

def calculate_risk(open_ports, ssl_issues, header_issues):
    score = 0

    for port in open_ports:
        score += 20 if port in HIGH_RISK_PORTS else 5

    # FIX: safely convert each item to string before checking
    ssl_problems = [
        i for i in ssl_issues
        if isinstance(i, str) and ("WARNING" in i or "Error" in i or "Not Found" in i)
    ]
    score += len(ssl_problems) * 15

    score += len(header_issues) * 8

    return min(score, 100)


# =====================================================
# RISK LEVEL CLASSIFICATION
# =====================================================

def get_risk_level(score):
    try:
        score = int(float(score))
    except (TypeError, ValueError):
        score = 0
    if score <= 25:
        return "LOW"
    elif score <= 50:
        return "MEDIUM"
    elif score <= 75:
        return "HIGH"
    return "CRITICAL"


# =====================================================
# FULL ANALYSIS WRAPPER
# =====================================================

def full_scan(target):
    ports = scan_ports(target)
    ssl_info = ssl_check(target)
    headers = header_check(target)
    risk_score = calculate_risk(ports, ssl_info, headers)

    return {
        "target": target,
        "ports": ports,
        "port_intelligence": analyze_ports(ports),
        "ssl": ssl_info,
        "headers": headers,
        "risk_score": risk_score,
        "risk_level": get_risk_level(risk_score),
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }