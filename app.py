from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    send_file,
    session,
    redirect,
    url_for,
    Response,
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
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded
from flask_cors import CORS
from dotenv import load_dotenv

from parser.policy_parser import normalize_policy
from core.policy_engine import analyze_policy
from database.db import save_scan, get_scan_history
from database.db import create_users_table, init_db
from auth.auth import auth
from utils.report_generator import generate_report
from utils.input_validator import (
    validate_filename,
    sanitize_input,
    validate_policy_rule,
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

# 🔴 FIX 1: Secure secret key
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))

# 🔴 FIX 2: Session security
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax"
)

app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

# 🔴 FIX 3: Enable CORS
CORS(app, resources={r"/*": {"origins": "*"}})

# Rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

app.register_blueprint(auth)

create_users_table()
init_db()


@app.errorhandler(RateLimitExceeded)
def handle_rate_limit_exceeded(e):
    return (
        jsonify(
            {
                "error": "Rate limit exceeded",
                "message": "Too many requests. Please wait.",
                "limit": "10 requests per minute",
            }
        ),
        429,
    )


@app.route("/")
def home():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
@limiter.limit("10 per minute")
def analyze():
    try:
        logging.info("Analyze route called")

        if "user_id" not in session:
            logging.error("Unauthorized access")
            return jsonify({"error": "Unauthorized access"}), 401

        uploaded_files = request.files.getlist("files")

        if not uploaded_files or uploaded_files[0].filename == "":
            return jsonify({"error": "No file uploaded"}), 400

        total_files = len(uploaded_files)

        rules = []
        file_details = []

        for uploaded_file in uploaded_files:
            filename = sanitize_input(uploaded_file.filename.lower())

            if not validate_filename(filename):
                continue

            content = uploaded_file.read()

            if not validate_file_content(content, filename):
                continue

            file_details.append(filename)

            try:
                if filename.endswith(".json"):
                    data = json.loads(content)
                    if "Statement" in data:
                        rules.extend(normalize_policy(data))

                elif filename.endswith(".yaml") or filename.endswith(".yml"):
                    data = yaml.safe_load(content)
                    if data and "Statement" in data:
                        rules.extend(normalize_policy(data))

                elif filename.endswith(".csv"):
                    decoded = content.decode("utf-8").splitlines()
                    reader = csv.DictReader(decoded)
                    for row in reader:
                        row = {k: sanitize_input(v) for k, v in row.items()}
                        rules.append(
                            {
                                "Effect": row.get("Effect", "Allow"),
                                "Action": row.get("Action", "*"),
                                "Resource": row.get("Resource", "*"),
                            }
                        )

                elif filename.endswith(".txt"):
                    text = content.decode("utf-8")
                    if "*" in text:
                        rules.append(
                            {
                                "Effect": "Allow",
                                "Action": "*",
                                "Resource": "*",
                            }
                        )
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

        if risk_score <= 30:
            risk_level = "LOW"
        elif risk_score <= 70:
            risk_level = "MEDIUM"
        else:
            risk_level = "HIGH"

        if username:
            try:
                save_scan(username, risk_score, risk_level, issues_count)
            except Exception as e:
                logging.error(f"DB save error: {str(e)}")

        response_data = {
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
        }

        return jsonify(response_data)

    except Exception as e:
        logging.error(traceback.format_exc())
        return jsonify({"error": "Server error"}), 500


@app.route("/download_report", methods=["POST"])
@limiter.limit("20 per minute")
def download_report():
    try:
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized access"}), 401

        data = request.get_json()

        if not data:
            return jsonify({"error": "No data provided"}), 400

        # 🔴 FIX: unique file
        filepath = f"report_{session.get('user_id')}.pdf"

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
        logging.info("History route called")

        # Session check
        if "user_id" not in session:
            return redirect(url_for("auth.login"))

        username = session.get("username")
        scans = get_scan_history(username)

        # Stats
        total_scans = len(scans)
        high_risk = len([s for s in scans if s[1] == "HIGH"])
        medium_risk = len([s for s in scans if s[1] == "MEDIUM"])
        low_risk = len([s for s in scans if s[1] == "LOW"])

        # Reverse latest first
        scans = list(reversed(scans))

        # Charts
        risk_scores = [scan[0] for scan in scans]
        timestamps = [scan[3] for scan in scans]

        fig = go.Figure()
        fig.add_trace(go.Scatter(x=timestamps, y=risk_scores, mode="lines+markers"))
        fig.update_layout(title="Risk Trend", template="plotly_dark")

        chart = plot(fig, output_type="div", include_plotlyjs=False)

        # Dummy service chart
        service_fig = go.Figure()
        service_fig.add_trace(go.Bar(x=["IAM","S3","EC2"], y=[5,3,2]))
        service_chart = plot(service_fig, output_type="div", include_plotlyjs=False)

        top_vulnerabilities = [("Security Issues", sum([s[2] for s in scans]))]

        # ✅ IMPORTANT: render_template
        return render_template(
            "history.html",
            scans=scans,
            chart=chart,
            service_chart=service_chart,
            total_scans=total_scans,
            high_risk=high_risk,
            medium_risk=medium_risk,
            low_risk=low_risk,
            top_vulnerabilities=top_vulnerabilities,
        )

    except Exception as e:
        logging.error(f"History error: {str(e)}")
        return f"<h2>Error loading history: {str(e)}</h2>"

# SECURITY HEADERS
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    return response


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)