import os
import sqlite3
from contextlib import contextmanager

from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE_DIR, "cyber.db")


@contextmanager
def get_connection():
    conn = sqlite3.connect(DB)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_connection() as conn:
        c = conn.cursor()

        c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            open_ports TEXT,
            ssl_issues TEXT,
            header_issues TEXT,
            risk_score INTEGER,
            timestamp TEXT,
            port_details TEXT
        )
        """)

        # Backward-compatible migration for existing cyber.db files.
        columns = {
            row[1] for row in c.execute("PRAGMA table_info(scans)").fetchall()
        }
        if "port_details" not in columns:
            c.execute("ALTER TABLE scans ADD COLUMN port_details TEXT")

        c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
        """)

        c.execute("""
        INSERT OR IGNORE INTO users (username, password)
        VALUES (?, ?)
        """, ("admin", generate_password_hash("admin123")))


def save_scan(target, ports, ssl, headers, risk, timestamp, port_details=""):
    with get_connection() as conn:
        conn.execute("""
        INSERT INTO scans
        (target, open_ports, ssl_issues, header_issues, risk_score, timestamp, port_details)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            target,
            ports,
            ssl,
            headers,
            int(risk),
            timestamp,
            port_details,
        ))


def get_all_scans():
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM scans ORDER BY id DESC"
        ).fetchall()


def get_scan(scan_id):
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()


def delete_scan(scan_id):
    with get_connection() as conn:
        cursor = conn.execute(
            "DELETE FROM scans WHERE id = ?", (scan_id,)
        )
        return cursor.rowcount


def delete_all_scans():
    with get_connection() as conn:
        cursor = conn.execute("DELETE FROM scans")
        return cursor.rowcount


def verify_user(username, password):
    with get_connection() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

    if user and check_password_hash(user[2], password):
        return user
    return None


def change_password(username, new_password):
    with get_connection() as conn:
        conn.execute(
            "UPDATE users SET password = ? WHERE username = ?",
            (generate_password_hash(new_password), username),
        )


def get_stats():
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT risk_score FROM scans"
        ).fetchall()

    low = medium = high = critical = 0

    for (score,) in rows:
        score = int(score or 0)
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
        "critical": critical,
    }
