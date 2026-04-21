import sqlite3
import logging

DB_NAME = "security_scans.db"


def get_connection():
    """Create a secure DB connection"""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row  # Better data handling
    return conn


def init_db():
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                risk_score INTEGER,
                risk_level TEXT,
                issues_count INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """
        )

        conn.commit()
    except Exception as e:
        logging.error(f"DB init error: {str(e)}")
    finally:
        conn.close()


def save_scan(username, risk_score, risk_level, issues_count):
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO scans (username, risk_score, risk_level, issues_count)
            VALUES (?, ?, ?, ?)
        """,
            (username, risk_score, risk_level, issues_count),
        )

        conn.commit()
    except Exception as e:
        logging.error(f"Error saving scan: {str(e)}")
    finally:
        conn.close()


def get_scan_history(username):
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT risk_score, risk_level, issues_count, timestamp
            FROM scans
            WHERE username = ?
            ORDER BY timestamp DESC
        """,
            (username,),
        )

        rows = cursor.fetchall()
        return [tuple(row) for row in rows]

    except Exception as e:
        logging.error(f"Error fetching history: {str(e)}")
        return []
    finally:
        conn.close()


def create_users_table():
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT
            )
        """
        )

        conn.commit()
    except Exception as e:
        logging.error(f"Error creating users table: {str(e)}")
    finally:
        conn.close()