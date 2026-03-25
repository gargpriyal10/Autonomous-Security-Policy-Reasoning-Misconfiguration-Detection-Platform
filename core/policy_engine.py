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
    # Risk score is now capped at 100, so max_risk should be 100
    max_risk = 100
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


def clean_markdown(text):
    """Remove markdown formatting like ##, ###, etc."""
    import re

    if not text:
        return text
    # Remove markdown headers
    text = re.sub(r"^#+\s+", "", text, flags=re.MULTILINE)
    # Remove bold markers
    text = text.replace("**", "")
    # Remove italic markers
    text = text.replace("*", "")
    return text


def format_recommendations(recommendations):
    """Format recommendations to readable strings"""
    formatted = []

    for rec in recommendations:
        if isinstance(rec, dict):
            # Format dictionary recommendations properly
            priority = rec.get("priority", "MEDIUM")
            title = rec.get("title", "")
            description = rec.get("description", "")
            impact = rec.get("impact", "")

            # Create formatted string
            rec_text = f"{title}"
            if description:
                rec_text += f" - {description}"
            if impact:
                rec_text += f" (Impact: {impact})"

            # Add priority badge
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
    # Detect misconfigurations
    issues, risk_score = detect_misconfigurations(rules)

    # -------- ADDITIONAL DATA PROTECTION & NETWORK SECURITY CHECKS --------
    for rule in rules:
        action = str(rule.get("Action", "")).lower()
        resource = str(rule.get("Resource", "")).lower()

        # Unrestricted S3 Access
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

        # Missing Encryption Enforcement
        if "s3:getobject" in action and "*" in resource:
            issues.append(
                {
                    "risk": "MEDIUM",
                    "problem": "Missing Encryption Enforcement",
                    "reason": "S3 objects may be accessed without encryption protection",
                    "service": "S3",
                    "severity": "Medium",
                }
            )
            risk_score += 10

        # Public Infrastructure Exposure
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

    # -------- POLICY CONFLICT DETECTION --------
    conflicts = detect_policy_conflicts(rules)
    issues.extend(conflicts)
    risk_score += len(conflicts) * 20

    # ========== CAP RISK SCORE AT 100 ==========
    risk_score = min(risk_score, 100)
    risk_score = max(risk_score, 0)  # Also ensure not negative

    # Generate AI explanation and clean markdown
    ai_text = generate_ai_explanation(issues)
    ai_text = clean_markdown(ai_text)

    ai_summary = generate_ai_summary(issues, risk_score)
    ai_summary = clean_markdown(ai_summary)

    # Generate recommendations
    recs = generate_recommendations(issues)

    service_risk = calculate_service_risk(issues)

    # Build policy graph
    G = build_graph(rules)

    # Simulate attack paths
    attack_paths = simulate_attack_paths(G)

    # -------- SECURITY POSTURE SCORE --------
    security_score = 100 - risk_score  # Simple inverse
    security_score = max(0, security_score)  # Cap at 0 minimum
    # ----------------------------------------

    # -------- SERVICE RISK ANALYTICS --------
    service_risk = service_risk_analytics(issues)
    # ----------------------------------------

    # ========== ENHANCED AI ANALYSIS ==========
    ai_analyzer = AIAnalyzer()
    enhanced_ai = ai_analyzer.analyze_issues(issues, risk_score, service_risk)

    # Get enhanced recommendations and format them
    enhanced_recommendations = enhanced_ai.get("recommendations", recs)
    formatted_recommendations = format_recommendations(enhanced_recommendations)

    # Get enhanced detailed analysis and clean markdown
    enhanced_detailed = enhanced_ai.get("detailed_analysis", ai_text)
    enhanced_detailed = clean_markdown(enhanced_detailed)

    # Get enhanced summary
    enhanced_summary = enhanced_ai.get("summary", ai_summary)
    enhanced_summary = clean_markdown(enhanced_summary)

    return {
        "issues": issues,
        "risk_score": risk_score,  # Now capped at 100
        "security_score": security_score,  # Now 100 - risk_score
        "ai_text": enhanced_detailed,
        "ai_summary": enhanced_summary,
        "recommendations": formatted_recommendations,  # Now properly formatted
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
        score = len(path) * 10  # simple risk scoring
        scored_paths.append({"path": path, "risk": score})

    scored_paths = sorted(scored_paths, key=lambda x: x["risk"], reverse=True)

    return scored_paths
