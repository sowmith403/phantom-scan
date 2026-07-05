import ast
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.pdfgen import canvas

from scanner import get_risk_level, PORT_INFO

WIDTH, HEIGHT = letter
MARGIN = 50
LINE_HEIGHT = 18

HIGH_RISK_PORTS = {21, 23, 135, 139, 445, 3389, 5900}


# =====================================================
# HELPERS
# =====================================================

def draw_wrapped_text(c, text, x, y, max_width, font="Helvetica", size=11):
    """Draw text with word wrapping. Returns new y position."""
    c.setFont(font, size)
    words = str(text).split()
    line = ""
    for word in words:
        test = f"{line} {word}".strip()
        if c.stringWidth(test, font, size) <= max_width:
            line = test
        else:
            c.drawString(x, y, line)
            y -= LINE_HEIGHT
            line = word
            if y < 60:
                c.showPage()
                y = HEIGHT - MARGIN
                c.setFont(font, size)
    if line:
        c.drawString(x, y, line)
        y -= LINE_HEIGHT
    return y


def draw_section_header(c, text, y):
    """Draw a colored section header bar."""
    c.setFillColor(colors.HexColor("#1a1a2e"))
    c.rect(MARGIN, y - 4, WIDTH - 2 * MARGIN, 22, fill=True, stroke=False)
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 13)
    c.drawString(MARGIN + 8, y + 2, text)
    c.setFillColor(colors.black)
    return y - 30


def risk_color(level):
    return {
        "LOW":      colors.HexColor("#27ae60"),
        "MEDIUM":   colors.HexColor("#f39c12"),
        "HIGH":     colors.HexColor("#e67e22"),
        "CRITICAL": colors.HexColor("#e74c3c"),
    }.get(level, colors.black)


def check_page(c, y, needed=40):
    """Start a new page if not enough space remains."""
    if y < needed + 60:
        c.showPage()
        draw_footer(c)
        return HEIGHT - MARGIN
    return y


def draw_footer(c):
    c.setFont("Helvetica-Oblique", 9)
    c.setFillColor(colors.grey)
    c.drawString(MARGIN, 35, "Generated automatically by CyberShield v2.0  |  Confidential")
    c.setFillColor(colors.black)


# =====================================================
# SAFE LIST PARSER
# Converts whatever comes out of the DB into a clean
# list-of-strings, no matter what the stored type is.
# =====================================================

def _safe_list(raw):
    """
    Always returns a list of strings.
    Handles: already a list, a stringified list/int/other,
    a plain int, None, or a bare string.
    """
    if raw is None:
        return []

    # Already a list — stringify every element
    if isinstance(raw, list):
        return [str(i) for i in raw if i is not None]

    # Plain integer stored directly (root cause of your crash)
    if isinstance(raw, int):
        return [str(raw)]

    # String that might be a Python literal
    if isinstance(raw, str):
        try:
            parsed = ast.literal_eval(raw)
            if isinstance(parsed, list):
                return [str(i) for i in parsed if i is not None]
            return [str(parsed)]
        except Exception:
            # Treat as a single plain-text item
            return [raw]

    # Fallback for anything else
    return [str(raw)]


# =====================================================
# DYNAMIC RECOMMENDATIONS
# =====================================================

def build_recommendations(ports, ssl_issues, header_issues):
    """
    All three arguments must already be clean lists.
    ports       -> list of ints
    ssl_issues  -> list of strings
    header_issues -> list of strings
    """
    recs = []

    missing_headers = {
        "Missing HSTS":                    "Enable Strict-Transport-Security (HSTS) to enforce HTTPS.",
        "Missing Content-Security-Policy": "Configure a Content-Security-Policy (CSP) header.",
        "Missing X-Frame-Options":         "Add X-Frame-Options to prevent clickjacking.",
        "Missing X-Content-Type-Options":  "Set X-Content-Type-Options: nosniff.",
        "Missing Referrer-Policy":         "Add a Referrer-Policy header to control referrer data.",
        "Missing Permissions-Policy":      "Add a Permissions-Policy header to restrict browser features.",
    }

    for issue in header_issues:
        for key, rec in missing_headers.items():
            if key in issue:
                recs.append(rec)

    risky_ports = {
        21:   "Disable FTP (port 21) - use SFTP instead.",
        23:   "Disable Telnet (port 23) - use SSH instead.",
        135:  "Close RPC port 135 - commonly exploited on Windows.",
        139:  "Close NetBIOS port 139 - not needed on modern systems.",
        445:  "Restrict SMB (port 445) - frequent ransomware vector.",
        3389: "Restrict RDP (port 3389) to VPN/trusted IPs only.",
        5900: "Close or restrict VNC (port 5900) - use encrypted alternatives.",
    }

    for port in ports:
        try:
            if int(port) in risky_ports:
                recs.append(risky_ports[int(port)])
        except (ValueError, TypeError):
            pass

    # Safe: ssl_issues is already guaranteed to be list-of-strings
    ssl_problems = [
        i for i in ssl_issues
        if "WARNING" in i or "Error" in i or "EXPIRED" in i
    ]
    if ssl_problems:
        recs.append("Renew or fix the SSL/TLS certificate immediately.")
        recs.append("Ensure TLS 1.2 or 1.3 is used - disable older protocols.")

    recs.append("Perform regular vulnerability scans and patch promptly.")
    return recs


# =====================================================
# MAIN REPORT GENERATOR
# =====================================================

def generate_report(scan_data, filename):
    target     = scan_data[0]
    ports_raw  = scan_data[1]
    ssl_raw    = scan_data[2]
    hdrs_raw   = scan_data[3]
    risk_score = scan_data[4]
    timestamp  = scan_data[5]

    # --- Normalise all lists to list-of-strings ---
    ports_list    = _safe_list(ports_raw)
    ssl_issues    = _safe_list(ssl_raw)
    header_issues = _safe_list(hdrs_raw)

    # ports need to be ints for dict lookups
    ports = []
    for p in ports_list:
        try:
            ports.append(int(p))
        except (ValueError, TypeError):
            pass

    risk_level = get_risk_level(risk_score)

    c = canvas.Canvas(filename, pagesize=letter)

    # ==========================================
    # COVER HEADER
    # ==========================================
    c.setFillColor(colors.HexColor("#1a1a2e"))
    c.rect(0, HEIGHT - 90, WIDTH, 90, fill=True, stroke=False)
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 22)
    c.drawString(MARGIN, HEIGHT - 45, "PhantomScan - Security Report")
    c.setFont("Helvetica", 11)
    c.drawString(MARGIN, HEIGHT - 68, "Cyber Security Monitoring & Vulnerability Assessment")
    c.setFillColor(colors.black)

    y = HEIGHT - 110

    # ==========================================
    # TARGET INFORMATION
    # ==========================================
    y = draw_section_header(c, "Target Information", y)
    c.setFont("Helvetica", 11)
    c.drawString(MARGIN + 10, y, f"Target:     {target}")
    y -= LINE_HEIGHT
    c.drawString(MARGIN + 10, y, f"Timestamp:  {timestamp}")
    y -= 30

    # ==========================================
    # RISK ASSESSMENT
    # ==========================================
    y = check_page(c, y)
    y = draw_section_header(c, "Risk Assessment", y)
    badge_color = risk_color(risk_level)
    c.setFillColor(badge_color)
    c.roundRect(MARGIN + 10, y - 8, 160, 28, 6, fill=True, stroke=False)
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(MARGIN + 20, y + 4, f"{risk_level}   {risk_score}/100")
    c.setFillColor(colors.black)
    y -= 40

    # ==========================================
    # OPEN PORTS
    # ==========================================
    y = check_page(c, y)
    y = draw_section_header(c, "Open Ports", y)
    if ports:
        for port in ports:
            service = PORT_INFO.get(port, "Unknown Service")
            flag = "  ⚠ High Risk" if port in HIGH_RISK_PORTS else ""
            y = check_page(c, y)
            c.setFont("Helvetica", 11)
            c.drawString(MARGIN + 10, y, f"  Port {port:<6} - {service}{flag}")
            y -= LINE_HEIGHT
    else:
        c.setFont("Helvetica", 11)
        c.drawString(MARGIN + 10, y, "  No open ports detected.")
        y -= LINE_HEIGHT
    y -= 12

    # ==========================================
    # SSL FINDINGS
    # ==========================================
    y = check_page(c, y)
    y = draw_section_header(c, "SSL / TLS Findings", y)
    if ssl_issues:
        for item in ssl_issues:
            y = check_page(c, y)
            y = draw_wrapped_text(c, f"  - {item}", MARGIN + 10, y, WIDTH - 2 * MARGIN - 20)
    else:
        c.setFont("Helvetica", 11)
        c.drawString(MARGIN + 10, y, "  No SSL/TLS issues detected.")
        y -= LINE_HEIGHT
    y -= 12

    # ==========================================
    # HEADER FINDINGS
    # ==========================================
    y = check_page(c, y)
    y = draw_section_header(c, "HTTP Security Headers", y)
    if header_issues:
        for item in header_issues:
            y = check_page(c, y)
            y = draw_wrapped_text(c, f"  - {item}", MARGIN + 10, y, WIDTH - 2 * MARGIN - 20)
    else:
        c.setFont("Helvetica", 11)
        c.drawString(MARGIN + 10, y, "  All required security headers are present.")
        y -= LINE_HEIGHT
    y -= 12

    # ==========================================
    # RECOMMENDATIONS
    # ==========================================
    y = check_page(c, y)
    y = draw_section_header(c, "Recommendations", y)
    recs = build_recommendations(ports, ssl_issues, header_issues)
    for i, rec in enumerate(recs, 1):
        y = check_page(c, y)
        y = draw_wrapped_text(c, f"  {i}. {rec}", MARGIN + 10, y, WIDTH - 2 * MARGIN - 20)
    y -= 12

    # ==========================================
    # FOOTER
    # ==========================================
    draw_footer(c)
    c.save()