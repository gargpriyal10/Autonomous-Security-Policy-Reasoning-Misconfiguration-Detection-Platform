from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for, Response
import json
import yaml
import csv
import plotly.express as px
from plotly.offline import plot

from parser.policy_parser import normalize_policy
from core.policy_engine import analyze_policy
from database.db import save_scan, get_scan_history
from database.db import create_users_table, init_db
from auth.auth import auth
from utils.report_generator import generate_report

app = Flask(__name__)
app.secret_key = "cloud_security_policy_platform_2026"


app.register_blueprint(auth)


create_users_table()
init_db()


@app.route("/")
def home():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized access"}), 401

    uploaded_file = request.files.get("file")

    if not uploaded_file:
        return jsonify({"error": "No file uploaded"})

    filename = uploaded_file.filename.lower()

    rules = []

    # JSON policy
    if filename.endswith(".json"):
        data = json.load(uploaded_file)

        if "Statement" in data:
            rules.extend(normalize_policy(data))

    # YAML policy
    elif filename.endswith(".yaml") or filename.endswith(".yml"):
        data = yaml.safe_load(uploaded_file)

        if data and "Statement" in data:
            rules.extend(normalize_policy(data))

    # CSV policy
    elif filename.endswith(".csv"):
        decoded = uploaded_file.read().decode("utf-8").splitlines()
        reader = csv.DictReader(decoded)

        for row in reader:
            rules.append(
                {
                    "Effect": row.get("Effect", "Allow"),
                    "Action": row.get("Action", "*"),
                    "Resource": row.get("Resource", "*"),
                }
            )

    # TXT policy
    elif filename.endswith(".txt"):
        text = uploaded_file.read().decode("utf-8")

        if "*" in text:
            rules.append({"Effect": "Allow", "Action": "*", "Resource": "*"})

    if not rules:
        return jsonify({"error": "Invalid policy file"})

    # Analyze policy
    result = analyze_policy(rules)

    # Remove graph from response (handled separately)
    result.pop("graph", None)

    username = session.get("username")

    risk_score = result["risk_score"]
    issues_count = len(result["issues"])

    # Determine risk level
    if risk_score <= 30:
        risk_level = "LOW"
    elif risk_score <= 70:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    # Save scan in database
    if username:
        save_scan(username, risk_score, risk_level, issues_count)

    return jsonify(
        {
            "risk_score": result["risk_score"],
            "security_score": result["security_score"],
            "issues": result["issues"],
            "recommendations": result["recommendations"],
            "attack_paths": result["attack_paths"],
            "service_risk": result["service_risk"],
            "ai_summary": result["ai_summary"],
            "ai_text": result["ai_text"],
        }
    )



@app.route("/download_report", methods=["POST"])
def download_report():
    data = request.get_json()

    filepath = "cloud_security_report.pdf"

    generate_report(data, filepath)

    return send_file(
        filepath,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="cloud_security_report.pdf"
    )

@app.route("/history")
def history():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    user_id = session.get("user_id")

    scans = get_scan_history(user_id)

    total_scans = len(scans)
    high_risk = len([s for s in scans if s[1] == "HIGH"])
    medium_risk = len([s for s in scans if s[1] == "MEDIUM"])
    low_risk = len([s for s in scans if s[1] == "LOW"])

    scans = list(reversed(scans))

    risk_scores = [scan[0] for scan in scans]
    timestamps = [scan[3] for scan in scans]

    # Create risk trend chart
    fig = px.line(
        x=timestamps,
        y=risk_scores,
        markers=True,
        title="Risk Score Trend"
    )

    fig.update_layout(
        xaxis_title="Time",
        yaxis_title="Risk Score",
        template="plotly_dark"
    )

    chart = plot(
        fig,
        output_type="div",
        include_plotlyjs=False,
        config={"displaylogo": False}
    )

    return render_template(
        "history.html",
        scans=scans,
        chart=chart,
        total_scans=total_scans,
        high_risk=high_risk,
        medium_risk=medium_risk,
        low_risk=low_risk
    )


@app.route("/export_csv")
def export_csv():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

user_id = session.get("user_id")

scans = get_scan_history(user_id)

def generate():
    data = [["Risk Score", "Risk Level", "Issues", "Time"]]

    for scan in scans:
        data.append([scan[0], scan[1], scan[2], scan[3]])

    for row in data:
        yield ",".join(map(str, row)) + "\n"

    return Response(
        generate(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=scan_history.csv"}
    )

if __name__ == "__main__":
    app.run(debug=True)
