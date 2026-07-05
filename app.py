from flask import (
    Flask, render_template, request,
    redirect, jsonify, send_file, session, flash
)

import time
import csv
import ast
import io

from db import init_db, save_scan, get_all_scans, get_scan, delete_scan, verify_user, get_stats

from scanner import (
    scan_ports, ssl_check, header_check,
    calculate_risk, get_risk_level, analyze_ports
)

from report import generate_report

app = Flask(__name__)
app.secret_key = "cybershield_secret_change_in_production"

init_db()


# ── AUTH DECORATOR ────────────────────────────────
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated


# ── HOME ──────────────────────────────────────────
@app.route("/")
def home():
    return render_template("index.html")


# ── LOGIN / LOGOUT ────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = verify_user(username, password)
        if user:
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
    target = request.form.get("target", "").strip()
    if not target:
        flash("Please enter a target.", "error")
        return redirect("/")
    try:
        ports        = scan_ports(target)
        ssl_findings = ssl_check(target)
        hdr_findings = header_check(target)
        risk_score   = calculate_risk(ports, ssl_findings, hdr_findings)
        save_scan(target, str(ports), str(ssl_findings), str(hdr_findings),
                  risk_score, time.strftime("%Y-%m-%d %H:%M:%S"))
    except Exception as e:
        print(f"SCAN ERROR: {e}")
        flash(f"Scan failed: {e}", "error")
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
        score = row[5]
        if   score <= 25: rc, rl = "low",      "LOW"
        elif score <= 50: rc, rl = "medium",   "MEDIUM"
        elif score <= 75: rc, rl = "high",     "HIGH"
        else:             rc, rl = "critical", "CRITICAL"

        try:    ports = ast.literal_eval(row[2])
        except: ports = []
        try:    ssl_list = ast.literal_eval(row[3])
        except: ssl_list = [row[3]] if row[3] else []
        try:    hdr_list = ast.literal_eval(row[4])
        except: hdr_list = [row[4]] if row[4] else []

        enriched.append({
            "id": row[0], "target": row[1],
            "ports": ports, "ssl": ssl_list, "headers": hdr_list,
            "score": score, "risk_class": rc, "risk_label": rl,
            "timestamp": row[6],
        })

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
    delete_scan(scan_id)
    return redirect("/dashboard")


# ── API: /api/scans  ← dashboard fetches this ─────
@app.route("/api/scans")
@login_required
def api_scans():
    rows = get_all_scans()
    result = []
    for row in rows:
        score = row[5]
        if   score <= 25: rl = "LOW"
        elif score <= 50: rl = "MEDIUM"
        elif score <= 75: rl = "HIGH"
        else:             rl = "CRITICAL"
        result.append({
            "id":         row[0],
            "target":     row[1],
            "ports":      row[2],
            "ssl":        row[3],
            "headers":    row[4],
            "risk":       score,
            "risk_level": rl,
            "time":       row[6],
        })
    return jsonify(result)


# ── API: /api/stats ───────────────────────────────
@app.route("/api/stats")
@login_required
def api_stats():
    return jsonify(get_stats())


# ── API: /api/results  (legacy alias) ────────────
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
    try:    ports = ast.literal_eval(row[2])
    except: ports = []
    return jsonify({
        "id": row[0], "target": row[1],
        "ports": ports, "services": analyze_ports(ports),
        "ssl": row[3], "headers": row[4],
        "risk_score": row[5], "risk_level": get_risk_level(row[5]),
        "timestamp": row[6],
    })


# ── API: live logs ────────────────────────────────
@app.route("/api/logs")
@login_required
def logs():
    scans = get_all_scans()
    return jsonify([{"target": s[1], "risk": s[5], "time": s[6]} for s in scans[:20]])


# ── PDF REPORT DOWNLOAD ───────────────────────────
@app.route("/report/<int:scan_id>")
@login_required
def report(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return "Scan not found", 404
    filename = f"report_{scan_id}.pdf"
    generate_report(scan, filename)
    return send_file(filename, as_attachment=True)


# ── EXPORT CSV  (in-memory — no temp file) ────────
@app.route("/export")
@login_required
def export_csv():
    rows = get_all_scans()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Target", "Open Ports", "SSL Findings",
                     "Header Findings", "Risk Score", "Timestamp"])
    writer.writerows(rows)
    output.seek(0)
    buf = io.BytesIO(output.getvalue().encode("utf-8"))
    buf.seek(0)
    fname = f"cybershield_export_{time.strftime('%Y%m%d_%H%M%S')}.csv"
    return send_file(buf, mimetype="text/csv", as_attachment=True, download_name=fname)


# ── HEALTH / VERSION ──────────────────────────────
@app.route("/health")
def health():
    return jsonify({"status": "online", "application": "PhantomScan"})

@app.route("/version")
def version():
    return jsonify({"name": "PhantomScan", "version": "2.0"})


# ── 404 ───────────────────────────────────────────
@app.errorhandler(404)
def not_found(error):
    return render_template("404.html"), 404


# ── MAIN ──────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 50)
    print("PhantomScan Starting...")
    print("http://127.0.0.1:5000")
    print("=" * 50)
    app.run(host="0.0.0.0", port=5000, debug=True)