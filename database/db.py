import sqlite3
import logging
from contextlib import contextmanager

DB_NAME = "security_scans.db"


# ---------------- CONNECTION HANDLER ----------------
@contextmanager
def get_connection():
    """
    Context-managed DB connection for safe open/close.
    """
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        yield conn
    except Exception as e:
        logging.exception(f"Database connection error: {str(e)}")
        raise
    finally:
        if conn:
            conn.close()


# ---------------- INITIALIZE DATABASE ----------------
def init_db():
    """
    Initialize database tables.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    risk_score INTEGER CHECK(risk_score >= 0),
                    risk_level TEXT,
                    issues_count INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)

            conn.commit()

    except Exception as e:
        logging.exception(f"DB init error: {str(e)}")


# ---------------- SAVE SCAN ----------------
def save_scan(username, risk_score, risk_level, issues_count):
    """
    Save scan result securely.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO scans (username, risk_score, risk_level, issues_count)
                VALUES (?, ?, ?, ?)
            """, (username, risk_score, risk_level, issues_count))

            conn.commit()

    except Exception as e:
        logging.exception(f"Error saving scan: {str(e)}")


# ---------------- GET HISTORY ----------------
def get_scan_history(username):
    """
    Fetch scan history for a user.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT risk_score, risk_level, issues_count, timestamp
                FROM scans
                WHERE username = ?
                ORDER BY timestamp DESC
            """, (username,))

            rows = cursor.fetchall()
            return [tuple(row) for row in rows]

    except Exception as e:
        logging.exception(f"Error fetching history: {str(e)}")
        return []


# ---------------- USERS TABLE ----------------
def create_users_table():
    """
    Create users table with secure schema.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL
                )
            """)

            conn.commit()

    except Exception as e:
        logging.exception(f"Error creating users table: {str(e)}")


# ---------------- OPTIONAL: CREATE USER ----------------
def create_user(username, hashed_password):
    """
    Register a new user securely.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO users (username, password)
                VALUES (?, ?)
            """, (username, hashed_password))

            conn.commit()

    except sqlite3.IntegrityError:
        return False
    except Exception as e:
        logging.exception(f"User creation error: {str(e)}")
        return False

    return True


# ---------------- OPTIONAL: GET USER ----------------
def get_user(username):
    """
    Fetch user details.
    """
    try:
        with get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT * FROM users WHERE username = ?
            """, (username,))

            return cursor.fetchone()

    except Exception as e:
        logging.exception(f"User fetch error: {str(e)}")
        return None