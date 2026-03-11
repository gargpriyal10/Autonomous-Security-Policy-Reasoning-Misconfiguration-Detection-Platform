from flask import Flask, render_template, request, jsonify
import json
import yaml
import csv

from parser.policy_parser import normalize_policy
from core.policy_engine import analyze_policy

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():

    uploaded_file = request.files.get("file")

    if not uploaded_file:
        return jsonify({"error": "No file uploaded"})

    filename = uploaded_file.filename.lower()

    rules = []

    # JSON file
    if filename.endswith(".json"):
        data = json.load(uploaded_file)

        if "Statement" in data:
            rules.extend(normalize_policy(data))

    # YAML file
    elif filename.endswith(".yaml") or filename.endswith(".yml"):
        data = yaml.safe_load(uploaded_file)

        if data and "Statement" in data:
            rules.extend(normalize_policy(data))

    # CSV file
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

    # TXT file
    elif filename.endswith(".txt"):
        text = uploaded_file.read().decode("utf-8")

        if "*" in text:
            rules.append({"Effect": "Allow", "Action": "*", "Resource": "*"})

    if not rules:
        return jsonify({"error": "Invalid policy file"})

    # Run policy analysis
    result = analyze_policy(rules)

    # Remove graph (NetworkX graph cannot be sent in JSON)
    result.pop("graph", None)

    return jsonify(
        {
            "risk_score": result["risk_score"],
            "security_score": result["security_score"],
            "issues": result["issues"],
            "recommendations": result["recommendations"],
            "attack_paths": result["attack_paths"],  # NEW
            "service_risk": result["service_risk"],  # NEW
            "ai_summary": result["ai_summary"],  # optional
        }
    )


if __name__ == "__main__":
    app.run(debug=True)
