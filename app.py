from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    send_file,
    session,
    redirect,
    url_for,
)
import json
import yaml
import csv
import pandas as pd
from plotly.offline import plot
import plotly.graph_objects as go
import traceback
import os
import logging
import uuid
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded
from flask_cors import CORS
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect

from parser.policy_parser import normalize_policy
from core.policy_engine import analyze_policy
from database.db import save_scan, get_scan_history
from database.db import create_users_table, init_db
from auth.auth import auth
from utils.report_generator import generate_report
from utils.input_validator import (
    validate_filename,
    sanitize_input,
    validate_file_content,
)

# Load env variables
load_dotenv()

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

app = Flask(__name__)

# ✅ Secure SECRET KEY
secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    raise ValueError("SECRET_KEY not set in environment")
app.secret_key = secret_key

# ✅ Session security
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800  # 30 min
)

app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

# ✅ Secure CORS
CORS(
    app,
    resources={r"/*": {"origins": ["http://localhost:5000"]}},
    supports_credentials=True
)

# ✅ CSRF Protection
csrf = CSRFProtect(app)

# Rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per day", "20 per hour"],
    storage_uri="memory://",
)

app.register_blueprint(auth)

create_users_table()
init_db()

# Allowed file types
ALLOWED_EXTENSIONS = {"json", "yaml", "yml", "csv", "txt"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1] in ALLOWED_EXTENSIONS


@app.errorhandler(RateLimitExceeded)
def handle_rate_limit_exceeded(e):
    return jsonify({
        "error": "Rate limit exceeded",
        "message": "Too many requests. Please wait."
    }), 429


@app.route("/")
def home():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
@limiter.limit("10 per minute")
def analyze():
    try:
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized access"}), 401

        uploaded_files = request.files.getlist("files")

        if not uploaded_files or uploaded_files[0].filename == "":
            return jsonify({"error": "No file uploaded"}), 400

        total_files = len(uploaded_files)

        rules = []
        file_details = []

        for uploaded_file in uploaded_files:
            filename = sanitize_input(uploaded_file.filename.lower())

            if not allowed_file(filename):
                continue

            if not validate_filename(filename):
                continue

            content = uploaded_file.read()

            # ✅ File size limit (2MB per file)
            if len(content) > 2 * 1024 * 1024:
                continue

            if not validate_file_content(content, filename):
                continue

            file_details.append(filename)

            try:
                if filename.endswith(".json"):
                    data = json.loads(content)
                    if "Statement" in data:
                        rules.extend(normalize_policy(data))

                elif filename.endswith((".yaml", ".yml")):
                    data = yaml.safe_load(content)
                    if data and "Statement" in data:
                        rules.extend(normalize_policy(data))

                elif filename.endswith(".csv"):
                    decoded = content.decode("utf-8").splitlines()
                    reader = csv.DictReader(decoded)
                    for row in reader:
                        row = {k: sanitize_input(v) for k, v in row.items()}
                        rules.append({
                            "Effect": row.get("Effect", "Allow"),
                            "Action": row.get("Action", "*"),
                            "Resource": row.get("Resource", "*"),
                        })

                elif filename.endswith(".txt"):
                    text = content.decode("utf-8")
                    if "*" in text:
                        rules.append({
                            "Effect": "Allow",
                            "Action": "*",
                            "Resource": "*",
                        })

            except Exception as e:
                logging.error(f"Error processing file {filename}: {str(e)}")
                continue

        if not rules:
            return jsonify({"error": "No valid policy rules found"}), 400

        result = analyze_policy(rules)
        result.pop("graph", None)

        username = session.get("username")
        risk_score = result.get("risk_score", 0)
        issues_count = len(result.get("issues", []))

        risk_level = (
            "LOW" if risk_score <= 30 else
            "MEDIUM" if risk_score <= 70 else
            "HIGH"
        )

        if username:
            try:
                save_scan(username, risk_score, risk_level, issues_count)
            except Exception as e:
                logging.error(f"DB save error: {str(e)}")

        return jsonify({
            "total_files": total_files,
            "files_analyzed": file_details,
            "risk_score": risk_score,
            "security_score": max(0, 100 - risk_score),
            "issues": result.get("issues", []),
            "recommendations": result.get("recommendations", []),
            "attack_paths": result.get("attack_paths", []),
            "service_risk": result.get("service_risk", {}),
            "ai_summary": result.get("ai_summary", ""),
            "ai_text": result.get("ai_text", ""),
        })

    except Exception:
        logging.error(traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500


@app.route("/download_report", methods=["POST"])
@limiter.limit("20 per minute")
def download_report():
    try:
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized access"}), 401

        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        # ✅ Safe unique file
        os.makedirs("reports", exist_ok=True)
        filename = f"{uuid.uuid4().hex}.pdf"
        filepath = os.path.join("reports", filename)

        generate_report(data, filepath)

        return send_file(
            filepath,
            mimetype="application/pdf",
            as_attachment=True,
            download_name="cloud_security_report.pdf",
        )

    except Exception as e:
        logging.error(f"Report error: {str(e)}")
        return jsonify({"error": "Report generation failed"}), 500


@app.route("/history")
def history():
    try:
        if "user_id" not in session:
            return redirect(url_for("auth.login"))

        username = session.get("username")
        scans = get_scan_history(username)

        scans = list(reversed(scans))

        risk_scores = [scan[0] for scan in scans]
        timestamps = [scan[3] for scan in scans]

        fig = go.Figure()
        fig.add_trace(go.Scatter(x=timestamps, y=risk_scores, mode="lines+markers"))
        fig.update_layout(title="Risk Trend", template="plotly_dark")

        chart = plot(fig, output_type="div", include_plotlyjs=False)

        return render_template(
            "history.html",
            scans=scans,
            chart=chart,
        )

    except Exception as e:
        logging.error(f"History error: {str(e)}")
        return "<h2>Error loading history</h2>"


# ✅ Security headers
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' https://cdn.plot.ly; style-src 'self' 'unsafe-inline';"
    )
    return response


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)