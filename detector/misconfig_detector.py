from collections import defaultdict


# ---------------- CONSTANTS ----------------

SEVERITY_SCORES = {
    "CRITICAL": 80,
    "HIGH": 40,
    "MEDIUM": 20,
    "LOW": 10,
}


DANGEROUS_PERMISSIONS = [
    "iam:PassRole",
    "iam:AttachRolePolicy",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "sts:AssumeRole",
]


# ---------------- HELPER FUNCTIONS ----------------

def add_issue(issues, seen, problem, service, severity, reason):
    """
    Add unique issue to list and return its risk score.
    """
    if problem in seen:
        return 0

    issues.append({
        "service": service,
        "risk": severity,
        "severity": severity,
        "problem": problem,
        "reason": reason,
    })

    seen.add(problem)
    return SEVERITY_SCORES.get(severity, 10)


def detect_service(action):
    """
    Identify cloud service from action string.
    """
    action = action.lower()

    mapping = {
        "s3": "S3",
        "ec2": "EC2",
        "iam": "IAM",
        "lambda": "Lambda",
        "dynamodb": "DynamoDB",
        "logs": "CloudWatch",
        "cloudwatch": "CloudWatch",
        "sns": "SNS",
        "sqs": "SQS",
    }

    for key, value in mapping.items():
        if action.startswith(key):
            return value

    return "Other"


# ---------------- MAIN DETECTOR ----------------

def detect_misconfigurations(rules):
    """
    Detect IAM misconfigurations and calculate risk score.
    """

    issues = []
    seen = set()
    risk_score = 0

    allow_map = defaultdict(set)
    deny_map = defaultdict(set)

    # -------- Build Permission Maps --------
    for rule in rules:
        effect = rule.get("Effect", "")
        action = str(rule.get("Action", ""))
        resource = str(rule.get("Resource", ""))

        if effect == "Allow":
            allow_map[action].add(resource)
        elif effect == "Deny":
            deny_map[action].add(resource)

    # -------- Conflict Detection --------
    for action in allow_map:
        if action in deny_map:
            risk_score += add_issue(
                issues,
                seen,
                f"Conflict: {action} has Allow & Deny",
                detect_service(action),
                "HIGH",
                "Conflicting permissions may lead to unpredictable access control",
            )

    # -------- Rule Analysis --------
    for rule in rules:
        effect = rule.get("Effect", "")
        action = str(rule.get("Action", ""))
        resource = str(rule.get("Resource", ""))

        service = detect_service(action)

        # Full Admin Access
        if effect == "Allow" and action == "*" and resource == "*":
            risk_score += add_issue(
                issues,
                seen,
                "Full Administrative Access",
                service,
                "CRITICAL",
                "Complete cloud takeover possible",
            )

        # Wildcard Action
        elif effect == "Allow" and "*" in action:
            risk_score += add_issue(
                issues,
                seen,
                f"Wildcard Permission: {action}",
                service,
                "HIGH",
                "Wildcard actions increase attack surface",
            )

        # All Resources Access
        elif effect == "Allow" and resource == "*":
            risk_score += add_issue(
                issues,
                seen,
                "Access to All Resources",
                service,
                "HIGH",
                "Resources are not restricted",
            )

        # Read-only access
        elif effect == "Allow" and ("get" in action.lower() or "list" in action.lower()):
            risk_score += add_issue(
                issues,
                seen,
                "Read-Only Access",
                service,
                "LOW",
                "Limited exposure but should be monitored",
            )

    # -------- Privilege Escalation --------
    for rule in rules:
        action = str(rule.get("Action", ""))

        for perm in DANGEROUS_PERMISSIONS:
            if perm.lower() in action.lower():
                risk_score += add_issue(
                    issues,
                    seen,
                    f"Privilege Escalation Risk: {perm}",
                    detect_service(action),
                    "CRITICAL",
                    "May allow attackers to escalate privileges",
                )

    return issues, min(risk_score, 100)


# ---------------- AI EXPLANATION ----------------

def generate_ai_explanation(issues):
    """
    Generate human-readable explanation of detected risks.
    """

    if not issues:
        return "System analysis shows secure configuration with minimal risk."

    severity_count = defaultdict(int)

    for issue in issues:
        severity_count[issue["risk"]] += 1

    explanation = []

    if severity_count["CRITICAL"]:
        explanation.append("Critical security risks detected.")
    if severity_count["HIGH"]:
        explanation.append("High-risk permissions found.")
    if severity_count["MEDIUM"]:
        explanation.append("Moderate misconfigurations identified.")
    if severity_count["LOW"]:
        explanation.append("Low-risk access patterns observed.")

    explanation.append("Follow least privilege principle.")

    return " ".join(explanation)


# ---------------- RECOMMENDATIONS ----------------

def generate_recommendations(issues):
    """
    Generate actionable security recommendations.
    """

    recs = set()

    for issue in issues:
        severity = issue["risk"]

        if severity == "CRITICAL":
            recs.add("Immediately remove administrative-level access.")
        elif severity == "HIGH":
            recs.add("Restrict wildcard permissions and scope access.")
        elif severity == "MEDIUM":
            recs.add("Review and clean redundant policies.")
        elif severity == "LOW":
            recs.add("Monitor read-only access regularly.")

    return list(recs) if recs else ["Configuration appears secure."]


# ---------------- POLICY CONFLICT DETECTOR ----------------

def detect_policy_conflicts(rules):
    """
    Detect conflicting IAM policies.
    """

    conflicts = []

    for i in range(len(rules)):
        for j in range(i + 1, len(rules)):

            r1, r2 = rules[i], rules[j]

            if (
                r1.get("Action") == r2.get("Action")
                and r1.get("Effect") != r2.get("Effect")
            ):
                conflicts.append({
                    "service": detect_service(r1.get("Action", "")),
                    "risk": "MEDIUM",
                    "severity": "MEDIUM",
                    "problem": f"Policy Conflict on action: {r1.get('Action')}",
                    "reason": "Conflicting Allow/Deny rules",
                })

    return conflicts


# ---------------- AI SUMMARY ----------------

def generate_ai_summary(issues, risk_score):
    """
    Generate summarized security report.
    """

    if not issues:
        return "No significant security risks detected."

    critical = sum(1 for i in issues if i["risk"] == "CRITICAL")
    high = sum(1 for i in issues if i["risk"] == "HIGH")

    summary = f"{len(issues)} issues detected with risk score {risk_score}. "

    if critical:
        summary += f"{critical} critical risks found. "
    if high:
        summary += f"{high} high-risk permissions detected. "

    summary += "Apply least privilege and restrict wildcard access."

    return summary