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
        
        # Password validation 
        if  len(password) < 4 or len(password) > 8:
            return render_template("register.html", error="Password must be between 4 and 8 characters")
        
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
            return render_template("register.html", error="Username already exists")
        conn.close()

        return redirect(url_for("auth.login"))
    return render_template("register.html")


@auth.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        #pqassword length validation
        if len(password) < 4 or len(password) > 8:
            return render_template("login.html", error="Password must be between 4 and 8 characters")

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username=?", (username,))

        user = cursor.fetchone()

        conn.close()

        if user and check_password_hash(user[2], password):

            session["user_id"] = user[0]
            session["username"] = user[1]

            return redirect("/")

        return render_template("login.html", error="Invalid username or password")
    return render_template("login.html")

@auth.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("auth.login"))
