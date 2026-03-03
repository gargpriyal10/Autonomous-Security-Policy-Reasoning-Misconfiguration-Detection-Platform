import sqlite3
from datetime import datetime


DB_NAME = "security_scans.db"


# ------------------ INIT DATABASE ------------------ #
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            issue_count INTEGER,
            timestamp TEXT
        )
    """)

    conn.commit()
    conn.close()


# ------------------ SAVE SCAN RESULT ------------------ #
def save_scan(username, risk_score, risk_level, issue_count):

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scan_history (username, risk_score, risk_level, issue_count, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (
        username,
        risk_score,
        risk_level,
        issue_count,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


# ------------------ FETCH HISTORY ------------------ #
def get_scan_history(username):

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT risk_score, risk_level, issue_count, timestamp
        FROM scan_history
        WHERE username = ?
        ORDER BY id DESC
    """, (username,))

    rows = cursor.fetchall()
    conn.close()

    return rows