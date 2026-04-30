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
from database.db import save_scan, get_scan_history, create_users_table, init_db
from auth.auth import auth
from utils.report_generator import generate_report
from utils.input_validator import (
    validate_filename,
    sanitize_input,
    validate_file_content,
)

# Load env
load_dotenv()

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

app = Flask(__name__)

# SECRET KEY
secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    raise ValueError("SECRET_KEY not set")
app.secret_key = secret_key

# Session Security
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800
)

app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

# CORS
CORS(
    app,
    resources={r"/*": {"origins": ["http://localhost:5000"]}},
    supports_credentials=True
)

# CSRF
csrf = CSRFProtect(app)

# Rate Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per day", "20 per hour"],
    storage_uri="memory://",
)

app.register_blueprint(auth)

create_users_table()
init_db()

ALLOWED_EXTENSIONS = {"json", "yaml", "yml", "csv", "txt"}


def allowed_file(filename):
    """Check if uploaded file has allowed extension."""
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS


@app.errorhandler(RateLimitExceeded)
def handle_rate_limit_exceeded(e):
    return jsonify({
        "error": "Rate limit exceeded",
        "message": "Too many requests. Please wait."
    }), 429


@app.route("/")
def home():
    """Render homepage if user is authenticated."""
    if not session.get("user_id"):
        return redirect(url_for("auth.login"))
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
@limiter.limit("10 per minute")
def analyze():
    """
    Analyze uploaded policy files and return security insights.
    """
    try:
        if not session.get("user_id"):
            return jsonify({"error": "Unauthorized access"}), 401

        # Request size protection
        if request.content_length and request.content_length > 5 * 1024 * 1024:
            return jsonify({"error": "Request too large"}), 413

        uploaded_files = request.files.getlist("files")

        if not uploaded_files or uploaded_files[0].filename == "":
            return jsonify({"error": "No file uploaded"}), 400

        total_files = len(uploaded_files)
        policy_rules = []
        file_details = []

        for uploaded_file in uploaded_files:
            filename = sanitize_input(uploaded_file.filename.lower())

            if not allowed_file(filename) or not validate_filename(filename):
                continue

            content = uploaded_file.read()

            if len(content) > 2 * 1024 * 1024:
                continue

            if not validate_file_content(content, filename):
                continue

            file_details.append(filename)

            try:
                if filename.endswith(".json"):
                    data = json.loads(content)
                    if "Statement" in data:
                        policy_rules.extend(normalize_policy(data))

                elif filename.endswith((".yaml", ".yml")):
                    data = yaml.safe_load(content)
                    if data and "Statement" in data:
                        policy_rules.extend(normalize_policy(data))

                elif filename.endswith(".csv"):
                    decoded = content.decode("utf-8").splitlines()
                    reader = csv.DictReader(decoded)
                    for row in reader:
                        row = {k: sanitize_input(v) for k, v in row.items()}
                        policy_rules.append({
                            "Effect": row.get("Effect", "Allow"),
                            "Action": row.get("Action", "*"),
                            "Resource": row.get("Resource", "*"),
                        })

                elif filename.endswith(".txt"):
                    text = content.decode("utf-8")
                    if "*" in text:
                        policy_rules.append({
                            "Effect": "Allow",
                            "Action": "*",
                            "Resource": "*",
                        })

            except Exception as e:
                logging.exception(f"File processing error: {filename}")
                continue

        if not policy_rules:
            return jsonify({"error": "No valid policy rules found"}), 400

        if len(policy_rules) > 5000:
            return jsonify({"error": "Too many rules submitted"}), 400

        result = analyze_policy(policy_rules)
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
            except Exception:
                logging.exception("DB save error")

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

    except Exception as e:
        logging.exception(f"Unexpected error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500


@app.route("/download_report", methods=["POST"])
@limiter.limit("20 per minute")
def download_report():
    """
    Generate and download PDF report securely.
    """
    try:
        if not session.get("user_id"):
            return jsonify({"error": "Unauthorized access"}), 401

        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        os.makedirs("reports", exist_ok=True)
        filename = f"{uuid.uuid4().hex}.pdf"
        filepath = os.path.join("reports", filename)

        generate_report(data, filepath)

        response = send_file(
            filepath,
            mimetype="application/pdf",
            as_attachment=True,
            download_name="cloud_security_report.pdf",
        )

        try:
            os.remove(filepath)
        except Exception:
            logging.warning("File cleanup failed")

        return response

    except Exception as e:
        logging.exception(f"Report error: {str(e)}")
        return jsonify({"error": "Report generation failed"}), 500


@app.route("/history")
def history():
    """
    Display user scan history with risk trends.
    """
    try:
        if not session.get("user_id"):
            return redirect(url_for("auth.login"))

        username = session.get("username")
        scans = list(reversed(get_scan_history(username)))

        risk_scores = [scan[0] for scan in scans]
        timestamps = [scan[3] for scan in scans]

        fig = go.Figure()
        fig.add_trace(go.Scatter(x=timestamps, y=risk_scores, mode="lines+markers"))
        fig.update_layout(title="Risk Trend", template="plotly_dark")

        chart = plot(fig, output_type="div", include_plotlyjs=False)

        return render_template("history.html", scans=scans, chart=chart)

    except Exception as e:
        logging.exception(f"History error: {str(e)}")
        return "<h2>Error loading history</h2>"


@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' https://cdn.plot.ly; style-src 'self' 'unsafe-inline';"
    )
    return response


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)