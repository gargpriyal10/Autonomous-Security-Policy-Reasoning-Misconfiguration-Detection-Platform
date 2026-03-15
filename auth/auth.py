from flask import Blueprint, render_template, request, redirect, url_for, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

auth = Blueprint("auth", __name__)

DATABASE = "security_scans.db"


def get_db():
    return sqlite3.connect(DATABASE)


@auth.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        hashed_password = generate_password_hash(password)

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hashed_password),
        )

        conn.commit()
        conn.close()

        return redirect(url_for("auth.login"))

    return render_template("register.html")


@auth.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username=?", (username,))

        user = cursor.fetchone()

        conn.close()

        if user and check_password_hash(user[2], password):

            session["user_id"] = user[0]
            session["username"] = user[1]

            return redirect("/")

    return render_template("login.html")


@auth.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("auth.login"))
