from detector.misconfig_detector import (
    detect_misconfigurations,
    generate_ai_explanation,
    generate_recommendations,
    detect_policy_conflicts,
    generate_ai_summary,
)

from graph.policy_graph import build_graph, simulate_attack_paths
from core.ai_analyzer import AIAnalyzer


# ---------------- SECURITY POSTURE SCORE ----------------
def calculate_security_score(risk_score):
    max_risk = 100
    return max(0, 100 - int((risk_score / max_risk) * 100))


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
            service_data[service]["risk_score"] += 30
        elif severity == "Medium":
            service_data[service]["risk_score"] += 20
        else:
            service_data[service]["risk_score"] += 10

    return service_data


# ---------------- REMOVE DUPLICATES ----------------
def remove_duplicate_issues(issues):
    seen = set()
    unique = []

    for issue in issues:
        key = (issue.get("problem"), issue.get("resource", ""), issue.get("service"))
        if key not in seen:
            seen.add(key)
            unique.append(issue)

    return unique


# ---------------- MAIN POLICY ANALYSIS ENGINE ----------------
def calculate_service_risk(issues):
    service_risk = {}

    for issue in issues:
        service = issue.get("service", "Other")

        if service not in service_risk:
            service_risk[service] = {"count": 0, "risk_score": 0}

        service_risk[service]["count"] += 1

        # Better weighted scoring
        severity = issue.get("severity", "Low")
        if severity == "High":
            service_risk[service]["risk_score"] += 30
        elif severity == "Medium":
            service_risk[service]["risk_score"] += 20
        else:
            service_risk[service]["risk_score"] += 10

    return service_risk


def clean_markdown(text):
    import re

    if not text:
        return text

    text = re.sub(r"^#+\s+", "", text, flags=re.MULTILINE)
    text = text.replace("**", "")
    text = text.replace("*", "")
    return text


def format_recommendations(recommendations):
    formatted = []

    for rec in recommendations:
        if isinstance(rec, dict):
            priority = rec.get("priority", "MEDIUM")
            title = rec.get("title", "")
            description = rec.get("description", "")
            impact = rec.get("impact", "")

            rec_text = f"{title}"
            if description:
                rec_text += f" - {description}"
            if impact:
                rec_text += f" (Impact: {impact})"

            if priority == "HIGH":
                rec_text = f"🔴 {rec_text}"
            elif priority == "MEDIUM":
                rec_text = f"🟠 {rec_text}"
            else:
                rec_text = f"🟡 {rec_text}"

            formatted.append(rec_text)
        elif isinstance(rec, str):
            formatted.append(rec)
        else:
            formatted.append(str(rec))

    return formatted


def analyze_policy(rules):
    issues, risk_score = detect_misconfigurations(rules)

    # -------- ADDITIONAL CHECKS --------
    for rule in rules:
        action = str(rule.get("Action", "")).lower()
        resource = str(rule.get("Resource", "")).lower()

        # Wildcard full access (VERY IMPORTANT)
        if "*" in action and "*" in resource:
            issues.append(
                {
                    "risk": "HIGH",
                    "problem": "Full Administrative Access",
                    "reason": "Policy allows full access to all resources",
                    "service": "IAM",
                    "severity": "High",
                }
            )
            risk_score += 40

        # S3 Public Access
        if "s3" in action and "*" in resource:
            issues.append(
                {
                    "risk": "MEDIUM",
                    "problem": "Unrestricted S3 Access",
                    "reason": "S3 resources exposed without restriction",
                    "service": "S3",
                    "severity": "Medium",
                }
            )
            risk_score += 15

        # EC2 Exposure
        if "*" in resource and "ec2" in action:
            issues.append(
                {
                    "risk": "HIGH",
                    "problem": "Public EC2 Exposure",
                    "reason": "EC2 instances may be publicly accessible",
                    "service": "EC2",
                    "severity": "High",
                }
            )
            risk_score += 25

    # -------- POLICY CONFLICTS --------
    conflicts = detect_policy_conflicts(rules)
    issues.extend(conflicts)
    risk_score += len(conflicts) * 15

    # -------- REMOVE DUPLICATES --------
    issues = remove_duplicate_issues(issues)

    # -------- CAP RISK SCORE --------
    risk_score = min(max(risk_score, 0), 100)

    # -------- AI OUTPUT --------
    ai_text = clean_markdown(generate_ai_explanation(issues))
    ai_summary = clean_markdown(generate_ai_summary(issues, risk_score))

    recs = generate_recommendations(issues)

    # -------- GRAPH --------
    G = build_graph(rules)
    attack_paths = simulate_attack_paths(G)

    # -------- SCORES --------
    security_score = calculate_security_score(risk_score)

    # -------- SERVICE ANALYTICS --------
    service_risk = service_risk_analytics(issues)

    # -------- AI ENHANCEMENT --------
    ai_analyzer = AIAnalyzer()
    enhanced_ai = ai_analyzer.analyze_issues(issues, risk_score, service_risk)

    enhanced_recommendations = enhanced_ai.get("recommendations", recs)
    formatted_recommendations = format_recommendations(enhanced_recommendations)

    enhanced_detailed = clean_markdown(
        enhanced_ai.get("detailed_analysis", ai_text)
    )

    enhanced_summary = clean_markdown(
        enhanced_ai.get("summary", ai_summary)
    )

    return {
        "issues": issues,
        "risk_score": risk_score,
        "security_score": security_score,
        "ai_text": enhanced_detailed,
        "ai_summary": enhanced_summary,
        "recommendations": formatted_recommendations,
        "service_risk": service_risk,
        "graph": G,
        "attack_paths": attack_paths,
        "risk_assessment": enhanced_ai.get(
            "risk_assessment", "Risk assessment not available"
        ),
        "priority_actions": enhanced_ai.get(
            "priority_actions", ["Review security issues"]
        ),
    }


def score_attack_paths(paths):
    scored_paths = []

    for path in paths:
        score = len(path) * 10
        scored_paths.append({"path": path, "risk": score})

    return sorted(scored_paths, key=lambda x: x["risk"], reverse=True)