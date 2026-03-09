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
def analyze_policy(rules):

    # Detect misconfigurations
    issues, risk_score = detect_misconfigurations(rules)
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
        "graph": G,
        "attack_paths": attack_paths,
        "service_risk": service_risk,
    }
