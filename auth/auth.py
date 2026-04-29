from flask import Blueprint, render_template, request, redirect, url_for, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import re
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

auth = Blueprint("auth", __name__)

DATABASE = "security_scans.db"

# ✅ Rate limiter for auth routes (anti brute-force)
limiter = Limiter(key_func=get_remote_address)


def get_db():
    return sqlite3.connect(DATABASE)


# ✅ Username validation
def is_valid_username(username):
    return re.match(r"^[a-zA-Z0-9_]{3,20}$", username)


# ✅ Strong password validation
def is_strong_password(password):
    return (
        len(password) >= 6
        and re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
        and re.search(r"[0-9]", password)
    )


@auth.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():

    if request.method == "POST":

        username = request.form["username"].strip()
        password = request.form["password"].strip()

        # ✅ Username validation
        if not is_valid_username(username):
            return render_template("register.html", error="Username must be 3-20 chars (letters, numbers, _)")

        # ✅ Strong password validation
        if not is_strong_password(password):
            return render_template(
                "register.html",
                error="Password must be at least 6 chars, include uppercase, lowercase and number",
            )

        hashed_password = generate_password_hash(password)

        conn = get_db()
        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed_password)
            )
            conn.commit()
        except:
            conn.close()
            return render_template("register.html", error="Username already exists")

        conn.close()

        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():

    if request.method == "POST":

        username = request.form["username"].strip()
        password = request.form["password"].strip()

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        user = cursor.fetchone()

        conn.close()

        if user and check_password_hash(user[2], password):

            session.clear()  # ✅ prevent session fixation
            session["user_id"] = user[0]
            session["username"] = user[1]

            return redirect("/")

        return render_template("login.html", error="Invalid username or password")

    return render_template("login.html")


@auth.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))