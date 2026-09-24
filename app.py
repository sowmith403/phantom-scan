import ast
import csv
import io
import os
import time
from functools import wraps

from flask import Flask, flash, jsonify, redirect, render_template, request, send_file, session

from db import (
    change_password,
    delete_all_scans,
    delete_scan,
    get_all_scans,
    get_scan,
    get_stats,
    init_db,
    save_scan,
    verify_user,
)
from report import generate_report
from scanner import (
    analyze_ports,
    calculate_risk,
    get_risk_level,
    header_check,
    normalize_target,
    scan_ports,
    ssl_check,
)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get(
    "PHANTOMSCAN_SECRET_KEY",
    "dev-only-change-this-secret-key",
)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("PHANTOMSCAN_COOKIE_SECURE") == "1"

init_db()


# ── AUTH DECORATOR ────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated


# ── SECURITY HEADERS ─────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return response


# ── HOME ──────────────────────────────────────────
@app.route("/")
@login_required
def home():
    return render_template("index.html")


# ── LOGIN / LOGOUT ────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("login.html")

        user = verify_user(username, password)
        if user:
            session.clear()
            session["user"] = username
            return redirect("/dashboard")

        flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ── SCAN ──────────────────────────────────────────
@app.route("/scan", methods=["POST"])
@login_required
def scan():
    raw_target = request.form.get("target", "").strip()

    try:
        target = normalize_target(raw_target)
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect("/")

    try:
        ports = scan_ports(target)
        ssl_findings = ssl_check(target)
        header_findings = header_check(target)
        risk_score = calculate_risk(ports, ssl_findings, header_findings)

        save_scan(
            target,
            str(ports),
            str(ssl_findings),
            str(header_findings),
            risk_score,
            time.strftime("%Y-%m-%d %H:%M:%S"),
        )
        flash(f"Scan completed for {target}.", "success")
    except Exception as exc:
        print(f"SCAN ERROR: {type(exc).__name__}: {exc}")
        flash(
            "Scan failed. Check that Nmap is installed and the target is reachable.",
            "error",
        )

    return redirect("/dashboard")


# ── DASHBOARD ─────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


# ── REPORTS PAGE ──────────────────────────────────
@app.route("/reports")
@login_required
def reports():
    rows = get_all_scans()
    enriched = []

    for row in rows:
        score = int(row[5] or 0)
        if score <= 25:
            rc, rl = "low", "LOW"
        elif score <= 50:
            rc, rl = "medium", "MEDIUM"
        elif score <= 75:
            rc, rl = "high", "HIGH"
        else:
            rc, rl = "critical", "CRITICAL"

        try:
            ports = ast.literal_eval(row[2]) if row[2] else []
            if not isinstance(ports, list):
                ports = []
        except (ValueError, SyntaxError):
            ports = []

        try:
            ssl_list = ast.literal_eval(row[3]) if row[3] else []
            if not isinstance(ssl_list, list):
                ssl_list = [str(ssl_list)]
        except (ValueError, SyntaxError):
            ssl_list = [row[3]] if row[3] else []

        try:
            hdr_list = ast.literal_eval(row[4]) if row[4] else []
            if not isinstance(hdr_list, list):
                hdr_list = [str(hdr_list)]
        except (ValueError, SyntaxError):
            hdr_list = [row[4]] if row[4] else []

        enriched.append(
            {
                "id": row[0],
                "target": row[1],
                "ports": ports,
                "ssl": ssl_list,
                "headers": hdr_list,
                "score": score,
                "risk_class": rc,
                "risk_label": rl,
                "timestamp": row[6],
            }
        )

    return render_template("reports.html", scans=enriched, stats=get_stats())


# ── THREAT INTEL ──────────────────────────────────
@app.route("/threat-intel")
@login_required
def threat_intel():
    return render_template("threat_intel.html")


# ── SETTINGS ──────────────────────────────────────
@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")


# ── HISTORY ───────────────────────────────────────
@app.route("/history")
@login_required
def history():
    return render_template("history.html", scans=get_all_scans())


# ── DELETE SCAN ───────────────────────────────────
@app.route("/delete/<int:scan_id>", methods=["POST"])
@login_required
def delete(scan_id):
    if get_scan(scan_id) is None:
        flash("Scan not found.", "error")
        return redirect("/dashboard")

    delete_scan(scan_id)
    flash(f"Scan #{scan_id} deleted.", "success")
    return redirect("/dashboard")


# ── DELETE ALL SCANS ──────────────────────────────
@app.route("/admin/delete-all", methods=["POST"])
@login_required
def delete_all():
    deleted = delete_all_scans()
    flash(f"Deleted {deleted} scan record(s).", "success")
    return redirect("/settings")


# ── CHANGE PASSWORD ───────────────────────────────
@app.route("/change-password", methods=["POST"])
@login_required
def update_password():
    current = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm = request.form.get("confirm_password", "")

    if not current or not new_password or not confirm:
        flash("All password fields are required.", "error")
        return redirect("/settings#account")

    if new_password != confirm:
        flash("New passwords do not match.", "error")
        return redirect("/settings#account")

    if len(new_password) < 8:
        flash("New password must contain at least 8 characters.", "error")
        return redirect("/settings#account")

    username = session["user"]
    if not verify_user(username, current):
        flash("Current password is incorrect.", "error")
        return redirect("/settings#account")

    change_password(username, new_password)
    flash("Password updated successfully. Please log in again.", "success")
    session.clear()
    return redirect("/login")


# ── API: /api/scans ───────────────────────────────
@app.route("/api/scans")
@login_required
def api_scans():
    rows = get_all_scans()
    result = []

    for row in rows:
        score = int(row[5] or 0)
        result.append(
            {
                "id": row[0],
                "target": row[1],
                "ports": row[2],
                "ssl": row[3],
                "headers": row[4],
                "risk": score,
                "risk_level": get_risk_level(score),
                "time": row[6],
            }
        )

    return jsonify(result)


# ── API: /api/stats ───────────────────────────────
@app.route("/api/stats")
@login_required
def api_stats():
    return jsonify(get_stats())


# ── API: /api/results (legacy alias) ──────────────
@app.route("/api/results")
@login_required
def api_results():
    return api_scans()


# ── API: single scan detail ───────────────────────
@app.route("/api/scan/<int:scan_id>")
@login_required
def scan_details(scan_id):
    row = get_scan(scan_id)
    if not row:
        return jsonify({"error": "Scan not found"}), 404

    try:
        ports = ast.literal_eval(row[2]) if row[2] else []
        if not isinstance(ports, list):
            ports = []
    except (ValueError, SyntaxError):
        ports = []

    score = int(row[5] or 0)
    return jsonify(
        {
            "id": row[0],
            "target": row[1],
            "ports": ports,
            "services": analyze_ports(ports),
            "ssl": row[3] or "",
            "headers": row[4] or "",
            "risk_score": score,
            "risk_level": get_risk_level(score),
            "timestamp": row[6],
        }
    )


# ── API: live logs ────────────────────────────────
@app.route("/api/logs")
@login_required
def logs():
    scans = get_all_scans()
    return jsonify(
        [
            {"target": s[1], "risk": int(s[5] or 0), "time": s[6]}
            for s in scans[:20]
        ]
    )


# ── PDF REPORT DOWNLOAD ───────────────────────────
@app.route("/report/<int:scan_id>")
@login_required
def report(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return "Scan not found", 404

    buffer = io.BytesIO()
    generate_report(scan, buffer)
    buffer.seek(0)

    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"phantomscan_report_{scan_id}.pdf",
    )


# ── EXPORT CSV ─────────────────────────────────────
@app.route("/export")
@login_required
def export_csv():
    rows = get_all_scans()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "ID",
            "Target",
            "Open Ports",
            "SSL Findings",
            "Header Findings",
            "Risk Score",
            "Timestamp",
        ]
    )
    writer.writerows(rows)
    buffer = io.BytesIO(output.getvalue().encode("utf-8"))
    buffer.seek(0)

    filename = f"phantomscan_export_{time.strftime('%Y%m%d_%H%M%S')}.csv"
    return send_file(
        buffer,
        mimetype="text/csv",
        as_attachment=True,
        download_name=filename,
    )


# ── HEALTH / VERSION ──────────────────────────────
@app.route("/health")
def health():
    return jsonify({"status": "online", "application": "PhantomScan"})


@app.route("/version")
def version():
    return jsonify({"name": "PhantomScan", "version": "2.1.0"})


# ── ERROR HANDLERS ────────────────────────────────
@app.errorhandler(404)
def not_found(error):
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500


# ── MAIN ──────────────────────────────────────────
if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    print("=" * 50)
    print("PhantomScan Starting...")
    print("http://127.0.0.1:5000")
    print("=" * 50)
    app.run(host="0.0.0.0", port=5000, debug=debug)
