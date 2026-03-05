from collections import defaultdict


# ---------------- MAIN DETECTOR ----------------
def detect_misconfigurations(rules):

    issues = []
    risk_score = 0
    seen = set()

    allow_map = defaultdict(list)
    deny_map = defaultdict(list)

    # -------- Build Permission Maps --------
    for rule in rules:
        effect = rule.get("Effect", "")
        action = str(rule.get("Action", ""))
        resource = str(rule.get("Resource", ""))

        if effect == "Allow":
            allow_map[action].append(resource)
        elif effect == "Deny":
            deny_map[action].append(resource)

    # -------- Conflict Detection --------
    for action in allow_map:
        if action in deny_map:
            problem = f"Conflict: {action} has Allow & Deny"

            if problem not in seen:
                issues.append(
                    {
                        "risk": "HIGH",
                        "problem": problem,
                        "reason": "Conflicting rules may create unpredictable access",
                    }
                )

                seen.add(problem)
                risk_score += 50

    # -------- Misconfiguration Detection --------
    for rule in rules:

        effect = rule.get("Effect", "")
        action = str(rule.get("Action", ""))
        resource = str(rule.get("Resource", ""))

        if effect == "Allow" and action == "*" and resource == "*":

            problem = "Full Admin Access"

            if problem not in seen:
                issues.append(
                    {
                        "risk": "CRITICAL",
                        "problem": problem,
                        "reason": "Complete cloud takeover possible",
                    }
                )

                seen.add(problem)

            risk_score += 120

        elif effect == "Allow" and "*" in action:

            problem = f"Wildcard Permission: {action}"

            if problem not in seen:
                issues.append(
                    {
                        "risk": "HIGH",
                        "problem": problem,
                        "reason": "Broad service access increases attack surface",
                    }
                )

                seen.add(problem)

            risk_score += 40

        elif effect == "Allow" and resource == "*":

            problem = "Access to All Resources"

            if problem not in seen:
                issues.append(
                    {
                        "risk": "HIGH",
                        "problem": problem,
                        "reason": "Access not restricted to specific assets",
                    }
                )

                seen.add(problem)

            risk_score += 35

        elif effect == "Allow" and ("Get" in action or "List" in action):

            problem = "Read-Only Access"

            if problem not in seen:
                issues.append(
                    {
                        "risk": "LOW",
                        "problem": problem,
                        "reason": "Limited data exposure risk",
                    }
                )

                seen.add(problem)

            risk_score += 10

    # -------- Privilege Escalation Detection --------
    dangerous_permissions = [
        "iam:PassRole",
        "iam:AttachRolePolicy",
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "sts:AssumeRole",
    ]

    for rule in rules:

        action = str(rule.get("Action", ""))

        for perm in dangerous_permissions:

            if perm.lower() in action.lower():

                problem = f"Privilege Escalation Risk: {perm}"

                if problem not in seen:

                    issues.append(
                        {
                            "risk": "CRITICAL",
                            "problem": problem,
                            "reason": "This permission can allow attackers to escalate privileges.",
                        }
                    )

                    seen.add(problem)
                    risk_score += 80

    return issues, risk_score


# ---------------- AI EXPLANATION ----------------
def generate_ai_explanation(issues):

    if not issues:
        return "System analysis shows secure configuration with minimal risk."

    explanation = ""

    for issue in issues:

        if issue["risk"] == "CRITICAL":
            explanation += "Critical administrative access detected. "

        elif issue["risk"] == "HIGH":
            explanation += "High-risk permissions detected. "

        elif issue["risk"] == "MEDIUM":
            explanation += "Moderate configuration redundancy found. "

        elif issue["risk"] == "LOW":
            explanation += "Low-risk read-only access detected. "

    explanation += "It is recommended to follow the least privilege principle."

    return explanation


# ---------------- RECOMMENDATIONS ----------------
def generate_recommendations(issues):

    recs = []

    for issue in issues:

        if issue["risk"] == "CRITICAL":
            recs.append("Immediately remove full administrative access.")

        elif issue["risk"] == "HIGH":
            recs.append("Avoid wildcard (*) permissions and restrict access.")

        elif issue["risk"] == "MEDIUM":
            recs.append("Remove redundant duplicate policy rules.")

        elif issue["risk"] == "LOW":
            recs.append("Review and monitor read-only access periodically.")

    if not recs:
        recs.append("Configuration appears secure.")

    return recs


# ---------------- POLICY CONFLICT DETECTOR ----------------
def detect_policy_conflicts(rules):

    conflicts = []

    for i in range(len(rules)):

        for j in range(i + 1, len(rules)):

            rule1 = rules[i]
            rule2 = rules[j]

            if rule1.get("Action") == rule2.get("Action") and rule1.get(
                "Effect"
            ) != rule2.get("Effect"):

                conflicts.append(
                    {
                        "risk": "MEDIUM",
                        "problem": f"Policy Conflict on action: {rule1.get('Action')}",
                        "reason": "One policy allows while another denies the same action",
                    }
                )

    return conflicts


# ---------------- AI SECURITY SUMMARY ----------------
def generate_ai_summary(issues, risk_score):

    if not issues:
        return "AI Analysis: No significant security risks detected. Cloud policies appear secure."

    summary = f"The analyzer detected {len(issues)} security issues with a total risk score of {risk_score}. "

    critical = sum(1 for i in issues if i["risk"] == "CRITICAL")
    high = sum(1 for i in issues if i["risk"] == "HIGH")

    if critical:
        summary += f"{critical} critical security risks were identified which may allow privilege escalation or full cloud compromise. "

    if high:
        summary += f"{high} high-risk permissions increase the attack surface of the cloud environment. "

    summary += "Applying the least privilege principle and restricting wildcard permissions is recommended."

    return summary
