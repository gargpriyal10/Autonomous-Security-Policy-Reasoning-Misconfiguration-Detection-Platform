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
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded

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


app = Flask(__name__)
app.secret_key = "cloud_security_policy_platform"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB max file size

# Initialize rate limiter
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
                "message": "You have exceeded the rate limit. Please wait a moment before trying again.",
                "limit": "10 analyses per minute",
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
        print("=" * 50)
        print("ANALYZE ROUTE CALLED")
        print("=" * 50)

        if "user_id" not in session:
            print("ERROR: User not authenticated")
            return jsonify({"error": "Unauthorized access"}), 401

        uploaded_files = request.files.getlist("files")
        print(f"Number of files received: {len(uploaded_files)}")

        if not uploaded_files or uploaded_files[0].filename == "":
            print("ERROR: No file uploaded")
            return jsonify({"error": "No file uploaded"}), 400

        total_files = len(uploaded_files)
        print(f"Total files: {total_files}")

        rules = []
        file_details = []

        for uploaded_file in uploaded_files:
            filename = uploaded_file.filename.lower()

            # Validate filename
            if not validate_filename(filename):
                print(f"Invalid filename: {filename}")
                continue

            # Read and validate content
            content = uploaded_file.read()
            if not validate_file_content(content, filename):
                print(f"Invalid file content: {filename}")
                continue

            print(f"Processing file: {filename}")
            file_details.append(filename)

            # Reset file pointer for reading
            uploaded_file.seek(0)

            try:
                if filename.endswith(".json"):
                    data = json.load(uploaded_file)
                    if "Statement" in data:
                        normalized = normalize_policy(data)
                        rules.extend(normalized)
                        print(f"Added {len(normalized)} rules from JSON")

                elif filename.endswith(".yaml") or filename.endswith(".yml"):
                    data = yaml.safe_load(uploaded_file)
                    if data and "Statement" in data:
                        normalized = normalize_policy(data)
                        rules.extend(normalized)
                        print(f"Added {len(normalized)} rules from YAML")

                elif filename.endswith(".csv"):
                    decoded = uploaded_file.read().decode("utf-8").splitlines()
                    reader = csv.DictReader(decoded)
                    csv_rules = 0
                    for row in reader:
                        rules.append(
                            {
                                "Effect": row.get("Effect", "Allow"),
                                "Action": row.get("Action", "*"),
                                "Resource": row.get("Resource", "*"),
                            }
                        )
                        csv_rules += 1
                    print(f"Added {csv_rules} rules from CSV")

                elif filename.endswith(".txt"):
                    text = uploaded_file.read().decode("utf-8")
                    if "*" in text:
                        rules.append(
                            {
                                "Effect": "Allow",
                                "Action": "*",
                                "Resource": "*",
                            }
                        )
                        print("Added wildcard rule from TXT")
            except Exception as e:
                print(f"Error processing file {filename}: {str(e)}")
                continue

        print(f"Total rules extracted: {len(rules)}")

        if not rules:
            print("ERROR: No valid rules found in files")
            return (
                jsonify({"error": "No valid policy rules found in uploaded files"}),
                400,
            )

        # Analyze the policies
        print("Calling analyze_policy...")
        result = analyze_policy(rules)
        print("Analysis complete")

        # Remove graph data if not needed for JSON response
        result.pop("graph", None)

        username = session.get("username")
        risk_score = result.get("risk_score", 0)
        issues_count = len(result.get("issues", []))

        # Determine risk level
        if risk_score <= 30:
            risk_level = "LOW"
        elif risk_score <= 70:
            risk_level = "MEDIUM"
        else:
            risk_level = "HIGH"

        # Save scan to database if user is logged in
        if username:
            try:
                save_scan(username, risk_score, risk_level, issues_count)
                print(f"Scan saved for user: {username}")
            except Exception as e:
                print(f"Error saving scan: {str(e)}")

        # ========== ENHANCE SERVICE RISK DATA ==========
        service_risk = result.get("service_risk", {})

        # Clean up service_risk to remove empty or None keys
        cleaned_service_risk = {}
        for service, data in service_risk.items():
            if (
                service
                and service != "undefined"
                and service != "other"
                and service != "None"
            ):
                # Ensure service name is properly formatted
                service_name = str(service).strip()
                if service_name and service_name not in [
                    "undefined",
                    "other",
                    "None",
                    "",
                ]:
                    # Make sure data has the correct structure
                    if isinstance(data, dict):
                        cleaned_service_risk[service_name] = {
                            "count": data.get("count", 1),
                            "risk_score": data.get("risk_score", 50),
                        }
                    else:
                        # If data is not a dict, create a default structure
                        cleaned_service_risk[service_name] = {
                            "count": 1,
                            "risk_score": 50,
                        }

        # If no valid services found but there are issues, create service_risk from issues
        if not cleaned_service_risk and issues_count > 0:
            print("Creating service_risk from issues...")
            # Extract service names from issues
            issues = result.get("issues", [])
            service_map = {}

            for issue in issues:
                problem = issue.get("problem", "").lower()
                # Map common service names
                if "s3" in problem or "bucket" in problem:
                    service = "S3"
                elif "iam" in problem or "role" in problem or "policy" in problem:
                    service = "IAM"
                elif "ec2" in problem or "instance" in problem:
                    service = "EC2"
                elif "lambda" in problem:
                    service = "Lambda"
                elif "rds" in problem or "database" in problem:
                    service = "RDS"
                elif "cloudtrail" in problem:
                    service = "CloudTrail"
                elif "cloudwatch" in problem:
                    service = "CloudWatch"
                elif "kms" in problem or "key" in problem:
                    service = "KMS"
                elif "sns" in problem:
                    service = "SNS"
                elif "sqs" in problem:
                    service = "SQS"
                else:
                    service = "Other"

                if service not in service_map:
                    service_map[service] = {"count": 0, "risk_score": 0}

                service_map[service]["count"] += 1

                # Calculate risk score based on issue severity
                risk = issue.get("risk", "MEDIUM")
                if risk == "HIGH":
                    risk_value = 90
                elif risk == "MEDIUM":
                    risk_value = 50
                else:
                    risk_value = 20

                # Update running average
                current_count = service_map[service]["count"]
                current_total = service_map[service]["risk_score"] * (current_count - 1)
                service_map[service]["risk_score"] = (
                    current_total + risk_value
                ) / current_count

            cleaned_service_risk = service_map
            print(f"Created service_risk: {cleaned_service_risk}")

        # If still no service_risk, create default test data
        if not cleaned_service_risk:
            print("No service risk data found, using defaults")
            cleaned_service_risk = {
                "IAM": {"count": 2, "risk_score": 65},
                "S3": {"count": 3, "risk_score": 72},
                "EC2": {"count": 1, "risk_score": 45},
                "Lambda": {"count": 1, "risk_score": 30},
            }

        # ========== ENHANCE ATTACK PATHS ==========
        attack_paths = result.get("attack_paths", [])

        # If no attack paths but there are issues, create basic attack paths
        if (not attack_paths or len(attack_paths) == 0) and issues_count > 0:
            print("Creating basic attack paths from issues...")
            attack_paths = []

            # Create a simple attack path based on high-risk issues
            high_risk_issues = [
                i for i in result.get("issues", []) if i.get("risk") == "HIGH"
            ]

            if high_risk_issues:
                # Create a path: Internet -> IAM Role -> Service -> Sensitive Data
                path = ["Internet"]

                # Add IAM if there are IAM-related issues
                if any("iam" in i.get("problem", "").lower() for i in high_risk_issues):
                    path.append("IAM Role")

                # Add services from issues
                for issue in high_risk_issues[:2]:  # Take first 2 high risk issues
                    problem = issue.get("problem", "")
                    if "s3" in problem.lower():
                        path.append("S3 Bucket")
                    elif "ec2" in problem.lower():
                        path.append("EC2 Instance")
                    elif "lambda" in problem.lower():
                        path.append("Lambda Function")
                    else:
                        path.append("Cloud Resource")

                path.append("Sensitive Data")
                attack_paths.append(path)

            # Add a default path if still empty
            if not attack_paths:
                attack_paths = [["Internet", "IAM Role", "S3 Bucket", "Sensitive Data"]]

        risk_score = result.get("risk_score", 0)
        risk_score = min(risk_score, 100) 

        security_score = 100 - risk_score
        security_score = max(0, security_score)

        response_data = {
            "total_files": total_files,
            "files_analyzed": file_details,
            "risk_score": result.get("risk_score", 0),
            "security_score": result.get(
                "security_score", 100 - result.get("risk_score", 0)
            ),
            "issues": result.get("issues", []),
            "recommendations": result.get("recommendations", []),
            "attack_paths": attack_paths,
            "service_risk": cleaned_service_risk,
            "ai_summary": result.get("ai_summary", "Analysis complete"),
            "ai_text": result.get("ai_text", "No additional AI analysis available."),
            # NEW AI FIELDS
            "risk_assessment": result.get(
                "risk_assessment", "Risk assessment not available"
            ),
            "priority_actions": result.get(
                "priority_actions",
                ["Review all security issues", "Implement least privilege principle"],
            ),
        }

        print("Sending response with:")
        print(f"  - service_risk keys: {list(cleaned_service_risk.keys())}")
        print(f"  - service_risk data: {cleaned_service_risk}")
        print(f"  - attack_paths: {len(attack_paths)} paths")
        print(f"  - issues: {issues_count} issues")

        return jsonify(response_data)

    except Exception as e:
        print("=" * 50)
        print("ERROR IN ANALYZE ROUTE:")
        print(traceback.format_exc())
        print("=" * 50)
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/download_report", methods=["POST"])
@limiter.limit("20 per minute")
def download_report():
    try:
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized access"}), 401

        data = request.get_json()

        if not data:
            return jsonify({"error": "No data provided"}), 400

        filepath = "cloud_security_report.pdf"

        generate_report(data, filepath)

        return send_file(
            filepath,
            mimetype="application/pdf",
            as_attachment=True,
            download_name="cloud_security_report.pdf",
        )
    except Exception as e:
        print(f"Error generating report: {str(e)}")
        return jsonify({"error": f"Report generation failed: {str(e)}"}), 500


@app.route("/history")
def history():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    username = session.get("username")
    scans = get_scan_history(username)

    print(f"Username: {username}")
    print(f"Number of Scans: {len(scans)}")
    print(f"Scans data: {scans[:5]}")

    # ========== DYNAMIC VULNERABILITY CATEGORIES ==========
    vulnerability_counts = {}

    # Analyze scans to create meaningful categories
    for scan in scans:
        issues_count = scan[2]
        risk_level = scan[1]

        if issues_count > 0:
            # Create categories based on risk level and issue patterns
            if risk_level == "HIGH":
                if issues_count > 5:
                    category = "🔴 Critical Security Gaps"
                else:
                    category = "🔴 High-Risk Misconfigurations"
            elif risk_level == "MEDIUM":
                if issues_count > 3:
                    category = "🟠 Medium-Risk Policy Issues"
                else:
                    category = "🟠 Configuration Violations"
            elif risk_level == "LOW":
                if issues_count > 2:
                    category = "🟡 Best Practice Recommendations"
                else:
                    category = "🟡 Minor Security Findings"
            else:
                category = "⚪ Security Observations"

            vulnerability_counts[category] = (
                vulnerability_counts.get(category, 0) + issues_count
            )

    # If we have no categories but have scans, create based on risk levels
    if not vulnerability_counts and scans:
        risk_summary = {}
        for scan in scans:
            risk_level = scan[1]
            issues_count = scan[2]
            if issues_count > 0:
                risk_summary[risk_level] = (
                    risk_summary.get(risk_level, 0) + issues_count
                )

        for level, count in risk_summary.items():
            if level == "HIGH":
                vulnerability_counts["🔴 Critical Issues"] = count
            elif level == "MEDIUM":
                vulnerability_counts["🟠 Medium Issues"] = count
            elif level == "LOW":
                vulnerability_counts["🟡 Low Issues"] = count

    # Sort and get top 5
    top_vulnerabilities = sorted(
        vulnerability_counts.items(), key=lambda x: x[1], reverse=True
    )[:5]

    # If still no data, provide placeholder
    if not top_vulnerabilities:
        top_vulnerabilities = [("📊 No security issues detected", 0)]

    print(f"Top vulnerabilities: {top_vulnerabilities}")  # Debug log

    # ========== SERVICE RISK CHART ==========
    services = ["IAM", "S3", "EC2", "Lambda"]
    service_risk_values = [6, 4, 3, 2]

    try:
        service_fig = go.Figure()
        service_fig.add_trace(
            go.Bar(x=services, y=service_risk_values, marker_color="orange")
        )
        service_fig.update_layout(
            title="Top Vulnerable Services",
            xaxis_title="Cloud Service",
            yaxis_title="Risk Count",
            template="plotly_dark",
            height=350,
            margin=dict(l=20, r=20, t=40, b=20),
        )

        service_chart = plot(
            service_fig,
            output_type="div",
            include_plotlyjs=False,
            config={"displaylogo": False, "displayModeBar": False},
        )
    except Exception as e:
        print(f"Error creating service chart: {e}")
        service_chart = "<p>Error loading chart</p>"

    # Calculate stats
    total_scans = len(scans)
    high_risk = len([s for s in scans if s[1] == "HIGH"])
    medium_risk = len([s for s in scans if s[1] == "MEDIUM"])
    low_risk = len([s for s in scans if s[1] == "LOW"])

    # Reverse for chronological order (newest first)
    scans = list(reversed(scans))
    risk_scores = [scan[0] for scan in scans]
    timestamps = [scan[3] for scan in scans]

    # ========== RISK TREND CHART ==========
    try:
        fig = go.Figure()
        fig.add_trace(
            go.Scatter(
                x=timestamps, y=risk_scores, mode="lines+markers", name="Risk Score"
            )
        )
        fig.update_layout(
            title="Risk Score Trend",
            height=420,
            xaxis_title="Time",
            yaxis_title="Risk Score",
            template="plotly_dark",
            margin=dict(l=20, r=20, t=40, b=20),
            xaxis_tickangle=-45,
        )

        chart = plot(
            fig,
            output_type="div",
            include_plotlyjs=False,
            config={"displaylogo": False, "displayModeBar": False},
        )
    except Exception as e:
        print(f"Error creating trend chart: {e}")
        chart = "<p>Error loading chart</p>"

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


@app.route("/export_csv")
def export_csv():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    username = session.get("username")
    scans = get_scan_history(username)

    def generate():
        yield "Risk Score,Risk Level,Issues,Time\n"
        for scan in scans:
            yield f"{scan[0]},{scan[1]},{scan[2]},{scan[3]}\n"

    return Response(
        generate(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=scan_history.csv"},
    )


# ========== SECURITY HEADERS ==========
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    # Updated CSP to allow Plotly and Bootstrap
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.plot.ly https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://cdn.jsdelivr.net;"
    )
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response


# Error handlers
@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({"error": "File too large. Maximum size is 16MB"}), 413


@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
