import sqlite3

DB_NAME = "security_scans.db"


def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            issues_count INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


def save_scan(username, risk_score, risk_level, issues_count):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scans (username, risk_score, risk_level, issues_count)
        VALUES (?, ?, ?, ?)
    """, (username, risk_score, risk_level, issues_count))

    conn.commit()
    conn.close()


def get_scan_history(username):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT risk_score, risk_level, issues_count, timestamp
        FROM scans
        WHERE username = ?
        ORDER BY timestamp DESC
    """, (username,))

    rows = cursor.fetchall()
    conn.close()

    return rows