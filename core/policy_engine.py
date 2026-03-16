from detector.misconfig_detector import (
    detect_misconfigurations,
    generate_ai_explanation,
    generate_recommendations,
    detect_policy_conflicts,
    generate_ai_summary,
)

from graph.policy_graph import build_graph, simulate_attack_paths


# ---------------- SECURITY POSTURE SCORE ----------------
def calculate_security_score(risk_score):

    max_risk = 150

    score = max(0, 100 - int((risk_score / max_risk) * 100))

    return score


# ---------------- SERVICE RISK ANALYTICS ----------------
def service_risk_analytics(issues):

    service_data = {}

    for issue in issues:

        service = issue.get("service", "Unknown")
        severity = issue.get("severity", "Low")

        if service not in service_data:
            service_data[service] = {"issues": 0, "risk_score": 0}

        service_data[service]["issues"] += 1

        if severity == "High":
            service_data[service]["risk_score"] += 3
        elif severity == "Medium":
            service_data[service]["risk_score"] += 2
        else:
            service_data[service]["risk_score"] += 1

    return service_data


# ---------------- MAIN POLICY ANALYSIS ENGINE ----------------
def calculate_service_risk(issues):

    service_risk = {}

    for issue in issues:

        service = issue.get("service", "Other")

        if service not in service_risk:
            service_risk[service] = {"count": 0, "risk_score": 0}

        service_risk[service]["count"] += 1
        service_risk[service]["risk_score"] += 10

    return service_risk


def analyze_policy(rules):

    # Detect misconfigurations
    issues, risk_score = detect_misconfigurations(rules)

    # -------- ADDITIONAL DATA PROTECTION & NETWORK SECURITY CHECKS --------
    for rule in rules:

        action = str(rule.get("Action", "")).lower()
        resource = str(rule.get("Resource", "")).lower()

        # Data Protection Check (S3 without restriction)
        if "s3" in action and "*" in resource:

            issues.append(
                {
                    "risk": "MEDIUM",
                    "problem": "Unrestricted S3 Access",
                    "reason": "Sensitive data storage may be exposed without encryption enforcement",
                    "service": "S3",
                    "severity": "Medium",
                }
            )

            risk_score += 10

        # Network Security Check (Public infrastructure exposure)
        if "*" in resource and ("ec2" in action or "network" in action):

            issues.append(
                {
                    "risk": "HIGH",
                    "problem": "Public Infrastructure Exposure",
                    "reason": "Cloud infrastructure may be accessible from the public internet",
                    "service": "EC2",
                    "severity": "High",
                }
            )

            risk_score += 20
    # ---------------------------------------------------------------------

    ai_summary = generate_ai_summary(issues, risk_score)

    # -------- POLICY CONFLICT DETECTION --------
    conflicts = detect_policy_conflicts(rules)

    issues.extend(conflicts)

    risk_score += len(conflicts) * 20
    # ------------------------------------------

    # Generate AI explanation
    ai_text = generate_ai_explanation(issues)

    # Generate recommendations
    recs = generate_recommendations(issues)

    service_risk = calculate_service_risk(issues)

    # Build policy graph
    G = build_graph(rules)

    # Simulate attack paths
    attack_paths = simulate_attack_paths(G)

    # -------- SECURITY POSTURE SCORE --------
    security_score = calculate_security_score(risk_score)
    # ----------------------------------------

    # -------- SERVICE RISK ANALYTICS --------
    service_risk = service_risk_analytics(issues)
    # ----------------------------------------

    return {
        "issues": issues,
        "risk_score": risk_score,
        "security_score": security_score,
        "ai_text": ai_text,
        "ai_summary": ai_summary,
        "recommendations": recs,
        "service_risk": service_risk,
        "graph": G,
        "attack_paths": attack_paths,
    }


def score_attack_paths(paths):

    scored_paths = []

    for path in paths:
        score = len(path) * 10  # simple risk scoring

        scored_paths.append({"path": path, "risk": score})

    scored_paths = sorted(scored_paths, key=lambda x: x["risk"], reverse=True)

    return scored_paths
