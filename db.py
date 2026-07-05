import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

DB = "cyber.db"


# =====================================================
# INIT DATABASE
# =====================================================

def init_db():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()

        c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            open_ports TEXT,
            ssl_issues TEXT,
            header_issues TEXT,
            risk_score INTEGER,
            timestamp TEXT
        )
        """)

        c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
        """)

        # Default admin â€” hashed password
        c.execute("""
        INSERT OR IGNORE INTO users (username, password)
        VALUES (?, ?)
        """, ("admin", generate_password_hash("admin123")))

        conn.commit()


# =====================================================
# SAVE SCAN
# =====================================================

def save_scan(target, ports, ssl, headers, risk, timestamp):
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("""
        INSERT INTO scans (target, open_ports, ssl_issues, header_issues, risk_score, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (target, ports, ssl, headers, risk, timestamp))
        conn.commit()


# =====================================================
# GET ALL SCANS
# =====================================================

def get_all_scans():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM scans ORDER BY id DESC")
        return c.fetchall()


# =====================================================
# GET SINGLE SCAN
# =====================================================

def get_scan(scan_id):
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM scans WHERE id=?", (scan_id,))
        return c.fetchone()


# =====================================================
# DELETE SCAN
# =====================================================

def delete_scan(scan_id):
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        conn.commit()


# =====================================================
# VERIFY USER (hashed password check)
# =====================================================

def verify_user(username, password):
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
    if user and check_password_hash(user[2], password):
        return user
    return None


# =====================================================
# GET STATS
# =====================================================

def get_stats():
    with sqlite3.connect(DB) as conn:
        c = conn.cursor()
        c.execute("SELECT risk_score FROM scans")
        rows = c.fetchall()

    low = medium = high = critical = 0
    for (score,) in rows:
        if score <= 25:
            low += 1
        elif score <= 50:
            medium += 1
        elif score <= 75:
            high += 1
        else:
            critical += 1

    return {
        "total": len(rows),
        "low": low,
        "medium": medium,
        "high": high,
        "critical": critical
    }