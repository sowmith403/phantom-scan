import json
import os
import re
import socket
import ssl
import time
from datetime import datetime
from urllib.parse import urlparse

import nmap
import requests


# Windows Nmap support. On other platforms, rely on PATH.
NMAP_PATH = r"C:\Program Files (x86)\Nmap"
if os.path.isdir(NMAP_PATH):
    os.environ["PATH"] = os.pathsep.join(
        [NMAP_PATH, os.environ.get("PATH", "")]
    )


PORT_INFO = {
    20: "FTP Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 135: "RPC", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 587: "SMTP Secure",
    993: "IMAPS", 995: "POP3S", 1433: "MS SQL", 1521: "Oracle DB",
    3306: "MySQL", 3389: "Remote Desktop", 5432: "PostgreSQL",
    5900: "VNC", 8080: "HTTP Alternate",
}

HIGH_RISK_PORTS = {21, 23, 135, 139, 445, 3389, 5900}
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9.-]+$")


def normalize_target(target):
    target = (target or "").strip()
    if not target:
        raise ValueError("Please enter a target.")

    candidate = target if "://" in target else f"//{target}"
    parsed = urlparse(candidate)
    hostname = parsed.hostname

    if not hostname:
        raise ValueError("Invalid target. Enter a domain name or IP address.")

    hostname = hostname.strip(".")
    if not HOSTNAME_RE.fullmatch(hostname):
        raise ValueError("Invalid target. Enter a valid hostname or IP address.")

    if len(hostname) > 253:
        raise ValueError("Target hostname is too long.")

    return hostname


def _port_risk(port):
    port = int(port)
    if port in HIGH_RISK_PORTS:
        return "HIGH"
    if port in {22, 25, 53, 110, 143, 161, 389, 1433, 1521, 3306, 5432}:
        return "MEDIUM"
    return "LOW"


def _service_recommendation(port):
    recommendations = {
        21: "Replace FTP with SFTP/FTPS or restrict access.",
        22: "Restrict SSH to trusted networks and use key authentication.",
        23: "Disable Telnet and use SSH instead.",
        25: "Restrict SMTP exposure and require secure mail transport.",
        80: "Redirect HTTP to HTTPS where appropriate.",
        135: "Restrict RPC to trusted networks.",
        139: "Disable or restrict legacy NetBIOS where possible.",
        443: "Review TLS configuration and certificate health.",
        445: "Restrict SMB to trusted networks.",
        3389: "Restrict RDP to VPN or trusted administrator IPs.",
        5900: "Restrict VNC and use encrypted remote access.",
    }
    return recommendations.get(
        int(port),
        "Verify that this service is required and restrict unnecessary exposure.",
    )


def scan_ports(target, include_details=False):
    """Run one efficient Nmap service scan and optionally return rich port intelligence.

    Uses Nmap's top-100 fast scan with lightweight service detection. This avoids
    the cost of a full 65,535-port scan while providing service/version details.
    """
    target = normalize_target(target)
    started = time.perf_counter()

    arguments = (
        "-sV --version-light -T4 -F --open "
        "--max-retries 2 --host-timeout 45s -n"
    )

    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments=arguments)

        open_ports = []
        port_details = []

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in sorted(nm[host][proto].keys()):
                    data = nm[host][proto][port]
                    if data.get("state") != "open":
                        continue

                    port = int(port)
                    service = data.get("name") or PORT_INFO.get(port, "Unknown")
                    product = data.get("product") or ""
                    version = data.get("version") or ""
                    extra = data.get("extrainfo") or ""
                    detected = " ".join(
                        part for part in (product, version, extra) if part
                    ).strip()

                    open_ports.append(port)
                    port_details.append({
                        "port": port,
                        "protocol": proto.upper(),
                        "state": data.get("state", "open").upper(),
                        "service": service,
                        "product": product,
                        "version": version,
                        "details": extra,
                        "detected": detected or "Service detected; version not reported",
                        "risk": _port_risk(port),
                        "risk_reason": (
                            "Commonly exposed administrative/legacy service"
                            if port in HIGH_RISK_PORTS
                            else "Review service exposure and necessity"
                        ),
                        "recommendation": _service_recommendation(port),
                    })

        duration = round(time.perf_counter() - started, 2)
        open_ports = sorted(set(open_ports))

        if not include_details:
            return open_ports

        return open_ports, {
            "scanner": "Nmap",
            "profile": "Fast top-100 + lightweight service detection",
            "arguments": arguments,
            "duration_seconds": duration,
            "open_count": len(open_ports),
            "ports": port_details,
        }

    except nmap.PortScannerError as exc:
        raise RuntimeError(
            "Nmap could not run. Verify that Nmap is installed and available in PATH."
        ) from exc
    except Exception as exc:
        raise RuntimeError(f"Port scan failed: {exc}") from exc


def analyze_ports(open_ports):
    return [
        f"Port {int(port)} ({PORT_INFO.get(int(port), 'Unknown Service')})"
        for port in open_ports
    ]


def ssl_check(target):
    target = normalize_target(target)
    results = []

    try:
        context = ssl.create_default_context()
        context.check_hostname = True

        with socket.create_connection((target, 443), timeout=5) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=target) as sock:
                cert = sock.getpeercert()

        if not cert:
            return ["Certificate Not Found"]

        issuer = dict(x[0] for x in cert.get("issuer", []))
        organization = issuer.get("organizationName", "Unknown")
        results.append(f"Issuer: {organization}")

        not_after = cert.get("notAfter", "")
        if not_after:
            results.append(f"Valid Until: {not_after}")
            expiry = datetime.strptime(
                not_after, "%b %d %H:%M:%S %Y %Z"
            )
            days_left = (expiry - datetime.utcnow()).days

            if days_left < 0:
                results.append("WARNING: Certificate is EXPIRED")
            elif days_left < 30:
                results.append("WARNING: Certificate expires in under 30 days")

    except ssl.SSLCertVerificationError:
        results.append("SSL Error: Certificate verification failed")
    except ssl.SSLError as exc:
        results.append(f"SSL Error: {exc}")
    except (socket.timeout, TimeoutError):
        results.append("Connection Error: TLS connection timed out")
    except (socket.gaierror, ConnectionRefusedError, OSError) as exc:
        results.append(f"Connection Error: {exc}")

    return results


REQUIRED_HEADERS = {
    "Content-Security-Policy": "Missing Content-Security-Policy",
    "Strict-Transport-Security": "Missing HSTS",
    "X-Frame-Options": "Missing X-Frame-Options",
    "X-Content-Type-Options": "Missing X-Content-Type-Options",
    "Referrer-Policy": "Missing Referrer-Policy",
    "Permissions-Policy": "Missing Permissions-Policy",
}


def header_check(target):
    target = normalize_target(target)
    url = f"https://{target}"

    findings = []
    try:
        response = requests.get(
            url,
            timeout=5,
            allow_redirects=True,
            headers={"User-Agent": "PhantomScan/2.2"},
        )

        for header, issue in REQUIRED_HEADERS.items():
            if header not in response.headers:
                findings.append(issue)

    except requests.exceptions.SSLError:
        findings.append("Connection Error: SSL verification failed")
    except requests.exceptions.Timeout:
        findings.append("Connection Error: HTTP request timed out")
    except requests.exceptions.ConnectionError:
        findings.append("Connection Error: Host unreachable")
    except requests.exceptions.RequestException as exc:
        findings.append(f"Connection Error: {exc}")

    return findings


def calculate_risk(open_ports, ssl_issues, header_issues):
    score = 0

    for port in open_ports:
        score += 20 if int(port) in HIGH_RISK_PORTS else 5

    ssl_problems = [
        item for item in ssl_issues
        if isinstance(item, str)
        and ("WARNING" in item or "Error" in item or "Not Found" in item)
    ]
    score += len(ssl_problems) * 15
    score += len(header_issues) * 8

    return min(max(score, 0), 100)


def get_risk_level(score):
    try:
        score = int(float(score))
    except (TypeError, ValueError):
        score = 0

    if score <= 25:
        return "LOW"
    if score <= 50:
        return "MEDIUM"
    if score <= 75:
        return "HIGH"
    return "CRITICAL"


def full_scan(target):
    target = normalize_target(target)
    ports, port_intelligence = scan_ports(target, include_details=True)
    ssl_info = ssl_check(target)
    headers = header_check(target)
    risk_score = calculate_risk(ports, ssl_info, headers)

    return {
        "target": target,
        "ports": ports,
        "port_intelligence": port_intelligence,
        "ssl": ssl_info,
        "headers": headers,
        "risk_score": risk_score,
        "risk_level": get_risk_level(risk_score),
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
