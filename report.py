import ast
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from scanner import HIGH_RISK_PORTS, PORT_INFO, get_risk_level

WIDTH, HEIGHT = letter
MARGIN = 50
LINE_HEIGHT = 18


def draw_wrapped_text(c, text, x, y, max_width, font="Helvetica", size=11):
    c.setFont(font, size)
    words = str(text).split()
    line = ""

    for word in words:
        test = f"{line} {word}".strip()
        if c.stringWidth(test, font, size) <= max_width:
            line = test
        else:
            if line:
                c.drawString(x, y, line)
                y -= LINE_HEIGHT
            line = word

            if y < 60:
                c.showPage()
                y = HEIGHT - MARGIN

    if line:
        c.drawString(x, y, line)
        y -= LINE_HEIGHT

    return y


def draw_section_header(c, text, y):
    c.setFillColor(colors.HexColor("#1a1a2e"))
    c.rect(
        MARGIN,
        y - 4,
        WIDTH - 2 * MARGIN,
        22,
        fill=True,
        stroke=False,
    )
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 13)
    c.drawString(MARGIN + 8, y + 2, text)
    c.setFillColor(colors.black)
    return y - 30


def risk_color(level):
    return {
        "LOW": colors.HexColor("#27ae60"),
        "MEDIUM": colors.HexColor("#f39c12"),
        "HIGH": colors.HexColor("#e67e22"),
        "CRITICAL": colors.HexColor("#e74c3c"),
    }.get(level, colors.black)


def check_page(c, y, needed=40):
    if y < needed + 60:
        c.showPage()
        return HEIGHT - MARGIN
    return y


def draw_footer(c):
    c.setFont("Helvetica-Oblique", 9)
    c.setFillColor(colors.grey)
    c.drawString(
        MARGIN,
        35,
        "Generated automatically by PhantomScan v2.1 | Confidential",
    )
    c.setFillColor(colors.black)


def _safe_list(raw):
    if raw is None:
        return []

    if isinstance(raw, list):
        return [str(item) for item in raw if item is not None]

    if isinstance(raw, int):
        return [str(raw)]

    if isinstance(raw, str):
        try:
            parsed = ast.literal_eval(raw)
            if isinstance(parsed, list):
                return [str(item) for item in parsed if item is not None]
            return [str(parsed)]
        except (ValueError, SyntaxError):
            return [raw]

    return [str(raw)]


def build_recommendations(ports, ssl_issues, header_issues):
    recommendations = []

    missing_headers = {
        "Missing HSTS":
            "Enable Strict-Transport-Security (HSTS) to enforce HTTPS.",
        "Missing Content-Security-Policy":
            "Configure a Content-Security-Policy (CSP) header.",
        "Missing X-Frame-Options":
            "Add X-Frame-Options to reduce clickjacking risk.",
        "Missing X-Content-Type-Options":
            "Set X-Content-Type-Options: nosniff.",
        "Missing Referrer-Policy":
            "Add a Referrer-Policy header to control referrer data.",
        "Missing Permissions-Policy":
            "Add a Permissions-Policy header to restrict browser features.",
    }

    for issue in header_issues:
        for key, recommendation in missing_headers.items():
            if key in issue:
                recommendations.append(recommendation)

    risky_ports = {
        21: "Disable FTP (port 21) or replace it with SFTP.",
        23: "Disable Telnet (port 23) and use SSH instead.",
        135: "Restrict RPC port 135 to trusted networks.",
        139: "Restrict or disable legacy NetBIOS port 139.",
        445: "Restrict SMB port 445 to trusted networks.",
        3389: "Restrict RDP port 3389 to VPN or trusted IPs.",
        5900: "Restrict VNC port 5900 and use encrypted access.",
    }

    for port in ports:
        if port in risky_ports:
            recommendations.append(risky_ports[port])

    ssl_problems = [
        item for item in ssl_issues
        if "WARNING" in item or "Error" in item or "EXPIRED" in item
    ]

    if ssl_problems:
        recommendations.append("Renew or fix the SSL/TLS certificate.")
        recommendations.append(
            "Use current secure TLS versions and disable obsolete protocols."
        )

    recommendations.append(
        "Perform regular vulnerability scans and patch identified issues."
    )
    return recommendations


def generate_report(scan_data, destination):
    # DB schema: id, target, open_ports, ssl_issues, header_issues,
    # risk_score, timestamp.
    _, target, ports_raw, ssl_raw, headers_raw, risk_score, timestamp = scan_data

    ports = []
    for item in _safe_list(ports_raw):
        try:
            ports.append(int(item))
        except (ValueError, TypeError):
            continue

    ssl_issues = _safe_list(ssl_raw)
    header_issues = _safe_list(headers_raw)
    risk_score = int(risk_score or 0)
    risk_level = get_risk_level(risk_score)

    c = canvas.Canvas(destination, pagesize=letter)

    c.setFillColor(colors.HexColor("#1a1a2e"))
    c.rect(0, HEIGHT - 90, WIDTH, 90, fill=True, stroke=False)
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 22)
    c.drawString(MARGIN, HEIGHT - 45, "PhantomScan - Security Report")
    c.setFont("Helvetica", 11)
    c.drawString(
        MARGIN,
        HEIGHT - 68,
        "Cyber Security Monitoring & Vulnerability Assessment",
    )
    c.setFillColor(colors.black)

    y = HEIGHT - 110

    y = draw_section_header(c, "Target Information", y)
    c.setFont("Helvetica", 11)
    c.drawString(MARGIN + 10, y, f"Target:     {target}")
    y -= LINE_HEIGHT
    c.drawString(MARGIN + 10, y, f"Timestamp:  {timestamp}")
    y -= 30

    y = check_page(c, y)
    y = draw_section_header(c, "Risk Assessment", y)
    c.setFillColor(risk_color(risk_level))
    c.roundRect(MARGIN + 10, y - 8, 160, 28, 6, fill=True, stroke=False)
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(MARGIN + 20, y + 4, f"{risk_level}   {risk_score}/100")
    c.setFillColor(colors.black)
    y -= 40

    y = check_page(c, y)
    y = draw_section_header(c, "Open Ports", y)

    if ports:
        for port in ports:
            y = check_page(c, y)
            service = PORT_INFO.get(port, "Unknown Service")
            flag = " [HIGH RISK]" if port in HIGH_RISK_PORTS else ""
            c.setFont("Helvetica", 11)
            c.drawString(
                MARGIN + 10,
                y,
                f"Port {port:<6} - {service}{flag}",
            )
            y -= LINE_HEIGHT
    else:
        c.setFont("Helvetica", 11)
        c.drawString(MARGIN + 10, y, "No open ports detected.")
        y -= LINE_HEIGHT

    y -= 12
    y = check_page(c, y)
    y = draw_section_header(c, "SSL / TLS Findings", y)

    if ssl_issues:
        for item in ssl_issues:
            y = check_page(c, y)
            y = draw_wrapped_text(
                c,
                f"- {item}",
                MARGIN + 10,
                y,
                WIDTH - 2 * MARGIN - 20,
            )
    else:
        c.setFont("Helvetica", 11)
        c.drawString(MARGIN + 10, y, "No SSL/TLS issues detected.")
        y -= LINE_HEIGHT

    y -= 12
    y = check_page(c, y)
    y = draw_section_header(c, "HTTP Security Headers", y)

    if header_issues:
        for item in header_issues:
            y = check_page(c, y)
            y = draw_wrapped_text(
                c,
                f"- {item}",
                MARGIN + 10,
                y,
                WIDTH - 2 * MARGIN - 20,
            )
    else:
        c.setFont("Helvetica", 11)
        c.drawString(
            MARGIN + 10,
            y,
            "All required security headers are present.",
        )
        y -= LINE_HEIGHT

    y -= 12
    y = check_page(c, y)
    y = draw_section_header(c, "Recommendations", y)

    recommendations = build_recommendations(
        ports,
        ssl_issues,
        header_issues,
    )

    for index, recommendation in enumerate(recommendations, 1):
        y = check_page(c, y)
        y = draw_wrapped_text(
            c,
            f"{index}. {recommendation}",
            MARGIN + 10,
            y,
            WIDTH - 2 * MARGIN - 20,
        )

    draw_footer(c)
    c.save()
