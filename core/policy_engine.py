from detector.misconfig_detector import (
    detect_misconfigurations,
    generate_ai_explanation,
    generate_recommendations,
    detect_policy_conflicts,
    generate_ai_summary,
)

from graph.policy_graph import build_graph, simulate_attack_paths
from core.ai_analyzer import AIAnalyzer
import re


# ---------------- UTILITY FUNCTIONS ----------------

def calculate_security_score(risk_score):
    """
    Convert risk score into security score (inverse relation).
    """
    return max(0, 100 - int(risk_score))


def clean_markdown(text):
    """
    Remove markdown formatting from AI-generated text.
    """
    if not text:
        return text

    text = re.sub(r"^#+\s+", "", text, flags=re.MULTILINE)
    text = text.replace("**", "").replace("*", "")
    return text.strip()


def remove_duplicate_issues(issues):
    """
    Remove duplicate issues based on problem, resource, and service.
    """
    seen = set()
    unique = []

    for issue in issues:
        key = (
            issue.get("problem"),
            issue.get("resource", ""),
            issue.get("service"),
        )
        if key not in seen:
            seen.add(key)
            unique.append(issue)

    return unique


def format_recommendations(recommendations):
    """
    Format recommendations with priority indicators.
    """
    formatted = []

    for rec in recommendations:
        if isinstance(rec, dict):
            priority = rec.get("priority", "MEDIUM")
            title = rec.get("title", "")
            description = rec.get("description", "")
            impact = rec.get("impact", "")

            text = f"{title}"
            if description:
                text += f" - {description}"
            if impact:
                text += f" (Impact: {impact})"

            prefix = "🟡"
            if priority == "HIGH":
                prefix = "🔴"
            elif priority == "MEDIUM":
                prefix = "🟠"

            formatted.append(f"{prefix} {text}")

        else:
            formatted.append(str(rec))

    return formatted


# ---------------- SECURITY RULE CHECKS ----------------

def apply_custom_security_checks(rules, issues, risk_score):
    """
    Add additional custom security checks beyond base detection.
    """
    for rule in rules:
        action = str(rule.get("Action", "")).lower()
        resource = str(rule.get("Resource", "")).lower()

        # Full access
        if "*" in action and "*" in resource:
            issues.append({
                "risk": "HIGH",
                "problem": "Full Administrative Access",
                "reason": "Policy allows full access to all resources",
                "service": "IAM",
                "severity": "High",
            })
            risk_score += 40

        # S3 public
        elif "s3" in action and "*" in resource:
            issues.append({
                "risk": "MEDIUM",
                "problem": "Unrestricted S3 Access",
                "reason": "S3 resources exposed",
                "service": "S3",
                "severity": "Medium",
            })
            risk_score += 15

        # EC2 exposure
        elif "ec2" in action and "*" in resource:
            issues.append({
                "risk": "HIGH",
                "problem": "Public EC2 Exposure",
                "reason": "EC2 instances may be publicly accessible",
                "service": "EC2",
                "severity": "High",
            })
            risk_score += 25

    return issues, risk_score


# ---------------- SERVICE ANALYTICS ----------------

def calculate_service_risk(issues):
    """
    Calculate service-wise risk analytics.
    """
    service_risk = {}

    for issue in issues:
        service = issue.get("service", "Other")
        severity = issue.get("severity", "Low")

        if service not in service_risk:
            service_risk[service] = {"count": 0, "risk_score": 0}

        service_risk[service]["count"] += 1

        if severity == "High":
            service_risk[service]["risk_score"] += 30
        elif severity == "Medium":
            service_risk[service]["risk_score"] += 20
        else:
            service_risk[service]["risk_score"] += 10

    return service_risk


# ---------------- MAIN ENGINE ----------------

def analyze_policy(rules):
    """
    Main function to analyze IAM policies and return security insights.
    """

    # Step 1: Base detection
    issues, risk_score = detect_misconfigurations(rules)

    # Step 2: Custom checks
    issues, risk_score = apply_custom_security_checks(rules, issues, risk_score)

    # Step 3: Conflict detection
    conflicts = detect_policy_conflicts(rules)
    issues.extend(conflicts)
    risk_score += len(conflicts) * 15

    # Step 4: Cleanup
    issues = remove_duplicate_issues(issues)
    risk_score = min(max(risk_score, 0), 100)

    # Step 5: AI outputs
    ai_text = clean_markdown(generate_ai_explanation(issues))
    ai_summary = clean_markdown(generate_ai_summary(issues, risk_score))

    # Step 6: Recommendations
    recommendations = generate_recommendations(issues)

    # Step 7: Graph analysis
    graph = build_graph(rules)
    attack_paths = simulate_attack_paths(graph)

    # Step 8: Scores
    security_score = calculate_security_score(risk_score)

    # Step 9: Service analytics
    service_risk = calculate_service_risk(issues)

    # Step 10: AI enhancement
    ai_analyzer = AIAnalyzer()
    enhanced = ai_analyzer.analyze_issues(issues, risk_score, service_risk)

    final_recommendations = format_recommendations(
        enhanced.get("recommendations", recommendations)
    )

    return {
        "issues": issues,
        "risk_score": risk_score,
        "security_score": security_score,
        "ai_text": clean_markdown(enhanced.get("detailed_analysis", ai_text)),
        "ai_summary": clean_markdown(enhanced.get("summary", ai_summary)),
        "recommendations": final_recommendations,
        "service_risk": service_risk,
        "graph": graph,
        "attack_paths": attack_paths,
        "risk_assessment": enhanced.get("risk_assessment", "Not available"),
        "priority_actions": enhanced.get("priority_actions", []),
    }


# ---------------- OPTIONAL ----------------

def score_attack_paths(paths):
    """
    Assign risk score to attack paths.
    """
    return sorted(
        [{"path": p, "risk": len(p) * 10} for p in paths],
        key=lambda x: x["risk"],
        reverse=True,
    )