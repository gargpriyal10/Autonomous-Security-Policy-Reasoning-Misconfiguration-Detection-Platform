from flask import Blueprint, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import re
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from database.db import get_connection, create_user, get_user

auth = Blueprint("auth", __name__)

# Rate limiter (anti brute-force)
limiter = Limiter(key_func=get_remote_address)


# ---------------- VALIDATION ----------------

def is_valid_username(username):
    """
    Validate username format (3-20 chars, alphanumeric + underscore).
    """
    return re.match(r"^[a-zA-Z0-9_]{3,20}$", username)


def is_strong_password(password):
    """
    Validate strong password.
    """
    return (
        len(password) >= 6
        and re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
        and re.search(r"[0-9]", password)
    )


# ---------------- REGISTER ----------------

@auth.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():
    """
    Handle user registration securely.
    """
    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        # Validation
        if not is_valid_username(username):
            return render_template(
                "register.html",
                error="Username must be 3-20 characters (letters, numbers, _)"
            )

        if not is_strong_password(password):
            return render_template(
                "register.html",
                error="Password must be 6+ chars with uppercase, lowercase & number"
            )

        try:
            hashed_password = generate_password_hash(password)

            success = create_user(username, hashed_password)

            if not success:
                return render_template(
                    "register.html",
                    error="Username already exists"
                )

            return redirect(url_for("auth.login"))

        except Exception as e:
            logging.exception(f"Registration error: {str(e)}")
            return render_template(
                "register.html",
                error="Something went wrong. Try again."
            )

    return render_template("register.html")


# ---------------- LOGIN ----------------

@auth.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    """
    Handle user login securely.
    """
    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        try:
            user = get_user(username)

            if user and check_password_hash(user["password"], password):

                session.clear()  # prevent session fixation
                session["user_id"] = user["id"]
                session["username"] = user["username"]

                session.permanent = True  # session timeout applies

                return redirect(url_for("home"))

            return render_template(
                "login.html",
                error="Invalid username or password"
            )

        except Exception as e:
            logging.exception(f"Login error: {str(e)}")
            return render_template(
                "login.html",
                error="Login failed. Try again."
            )

    return render_template("login.html")


# ---------------- LOGOUT ----------------

@auth.route("/logout")
def logout():
    """
    Clear session and logout user.
    """
    session.clear()
    return redirect(url_for("auth.login"))