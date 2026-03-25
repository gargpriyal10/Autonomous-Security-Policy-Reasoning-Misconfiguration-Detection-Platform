import random
import re


class AIAnalyzer:
    """Enhanced AI analysis for security policies"""

    def __init__(self):
        pass

    def analyze_issues(self, issues, risk_score, service_risk):
        """Generate comprehensive AI analysis"""

        if not issues:
            return {
                "summary": "✅ No security issues detected! Your policies appear to be well-configured.",
                "recommendations": ["Continue following security best practices"],
                "detailed_analysis": "All analyzed policies comply with security best practices. No misconfigurations found.",
                "risk_assessment": "Low",
                "priority_actions": ["Schedule regular policy reviews"],
            }

        # Categorize issues by severity
        high_risk = [i for i in issues if i.get("risk") == "HIGH"]
        medium_risk = [i for i in issues if i.get("risk") == "MEDIUM"]
        low_risk = [i for i in issues if i.get("risk") == "LOW"]

        # Generate AI summary based on issues
        summary = self._generate_summary(high_risk, medium_risk, low_risk, risk_score)

        # Generate recommendations
        recommendations = self._generate_recommendations(issues, service_risk)

        # Generate detailed analysis
        detailed_analysis = self._generate_detailed_analysis(issues, service_risk)

        # Risk assessment
        risk_assessment = self._assess_risk(high_risk, medium_risk, risk_score)

        # Priority actions
        priority_actions = self._get_priority_actions(high_risk, issues)

        return {
            "summary": summary,
            "recommendations": recommendations,
            "detailed_analysis": detailed_analysis,
            "risk_assessment": risk_assessment,
            "priority_actions": priority_actions,
        }

    def _generate_summary(self, high_risk, medium_risk, low_risk, risk_score):
        """Generate executive summary"""

        total_high = len(high_risk)
        total_medium = len(medium_risk)
        total_low = len(low_risk)
        total_issues = total_high + total_medium + total_low

        if total_high > 0:
            severity = "CRITICAL"
            tone = "⚠️ URGENT ACTION REQUIRED"
        elif total_medium > 2:
            severity = "HIGH"
            tone = "⚠️ Important Issues Detected"
        elif total_medium > 0:
            severity = "MEDIUM"
            tone = "📌 Medium Risk Findings"
        else:
            severity = "LOW"
            tone = "ℹ️ Minor Recommendations"

        summary = f"{tone}\n\n"
        summary += f"Analysis completed with {total_issues} security findings.\n"
        summary += f"- 🔴 HIGH Risk: {total_high}\n"
        summary += f"- 🟠 MEDIUM Risk: {total_medium}\n"
        summary += f"- 🟡 LOW Risk: {total_low}\n\n"
        summary += f"Overall Risk Score: {risk_score}/100 ({severity} Severity)\n\n"

        if total_high > 0:
            summary += "🚨 CRITICAL: Immediate attention required! High-risk misconfigurations detected that could lead to security breaches."
        elif total_medium > 0:
            summary += "⚠️ Important: Medium-risk issues identified. Recommend addressing these within the next week."
        else:
            summary += "✅ Low-risk findings. Consider implementing recommendations for better security posture."

        return summary

    def _generate_recommendations(self, issues, service_risk):
        """Generate actionable recommendations"""

        recommendations = []

        # Analyze issues by type
        wildcard_issues = [
            i
            for i in issues
            if "wildcard" in i.get("problem", "").lower() or "*" in i.get("problem", "")
        ]
        public_issues = [i for i in issues if "public" in i.get("problem", "").lower()]
        privilege_issues = [
            i
            for i in issues
            if "privilege" in i.get("problem", "").lower()
            or "admin" in i.get("problem", "").lower()
        ]

        # Wildcard permissions
        if wildcard_issues:
            recommendations.append(
                {
                    "priority": "HIGH",
                    "title": "Remove Wildcard Permissions",
                    "description": f"Found {len(wildcard_issues)} policies using wildcard (*) permissions. Replace with specific actions.",
                    "impact": "Prevents excessive permissions and reduces attack surface",
                }
            )

        # Public exposure
        if public_issues:
            recommendations.append(
                {
                    "priority": "HIGH",
                    "title": "Restrict Public Access",
                    "description": f"Found {len(public_issues)} policies allowing public access. Implement proper access controls.",
                    "impact": "Prevents unauthorized access to sensitive resources",
                }
            )

        # Privilege escalation
        if privilege_issues:
            recommendations.append(
                {
                    "priority": "HIGH",
                    "title": "Review Privilege Escalation Risks",
                    "description": f"Found {len(privilege_issues)} potential privilege escalation paths. Implement least privilege principle.",
                    "impact": "Reduces risk of attackers gaining elevated access",
                }
            )

        # Service-specific recommendations
        if service_risk:
            highest_risk_service = (
                max(service_risk.items(), key=lambda x: x[1].get("risk_score", 0))
                if service_risk
                else None
            )
            if highest_risk_service:
                recommendations.append(
                    {
                        "priority": "MEDIUM",
                        "title": f"Focus on {highest_risk_service[0]} Security",
                        "description": f"Service '{highest_risk_service[0]}' has the highest risk score ({highest_risk_service[1].get('risk_score', 0)}). Review its policies.",
                        "impact": "Targets the most vulnerable service",
                    }
                )

        # General recommendations
        if not recommendations:
            recommendations.append(
                {
                    "priority": "LOW",
                    "title": "Regular Policy Reviews",
                    "description": "Schedule periodic reviews of all IAM policies to ensure compliance.",
                    "impact": "Maintains security posture over time",
                }
            )

        # Add best practices
        recommendations.append(
            {
                "priority": "MEDIUM",
                "title": "Enable MFA for All Users",
                "description": "Require Multi-Factor Authentication for all IAM users.",
                "impact": "Adds extra layer of security against credential compromise",
            }
        )

        return recommendations

    def _generate_detailed_analysis(self, issues, service_risk):
        """Generate detailed technical analysis"""

        analysis = "Detailed Security Analysis\n\n"

        # Risk distribution
        high_risk_issues = [i for i in issues if i.get("risk") == "HIGH"]
        medium_risk_issues = [i for i in issues if i.get("risk") == "MEDIUM"]

        if high_risk_issues:
            analysis += "🔴 High-Risk Issues (Critical)\n\n"
            for i, issue in enumerate(high_risk_issues[:3], 1):
                analysis += f"{i}. **{issue.get('problem', 'Unknown')}**\n"
                analysis += f"   - {issue.get('reason', 'No details provided')}\n\n"

        if medium_risk_issues:
            analysis += "🟠 Medium-Risk Issues\n\n"
            for i, issue in enumerate(medium_risk_issues[:3], 1):
                analysis += f"{i}. **{issue.get('problem', 'Unknown')}**\n"
                analysis += f"   - {issue.get('reason', 'No details provided')}\n\n"

        # Service risk analysis
        if service_risk:
            analysis += "📊 Service Risk Analysis\n\n"
            sorted_services = sorted(
                service_risk.items(),
                key=lambda x: x[1].get("risk_score", 0),
                reverse=True,
            )
            for service, data in sorted_services[:3]:
                analysis += f"- **{service}**: Risk Score {data.get('risk_score', 0)} ({data.get('issues', 0)} issues)\n"

        return analysis

    def _assess_risk(self, high_risk, medium_risk, risk_score):
        """Assess overall risk level"""

        if high_risk:
            return "CRITICAL - Immediate action required"
        elif risk_score > 70:
            return "HIGH - Address within 24 hours"
        elif risk_score > 40:
            return "MEDIUM - Address within 1 week"
        elif risk_score > 20:
            return "LOW - Address within next sprint"
        else:
            return "MINIMAL - No urgent action needed"

    def _get_priority_actions(self, high_risk, issues):
        """Get prioritized action items"""

        actions = []

        if high_risk:
            for issue in high_risk[:2]:
                problem = issue.get("problem", "Unknown issue")
                actions.append(f"🚨 Fix: {problem}")

        # Add common priority actions
        if any("wildcard" in i.get("problem", "").lower() for i in issues):
            actions.append("🔧 Replace wildcard (*) permissions with specific actions")

        if any("public" in i.get("problem", "").lower() for i in issues):
            actions.append("🔒 Remove public access from S3 buckets and IAM policies")

        if not actions:
            actions.append("✅ Continue regular security reviews")
            actions.append("📊 Monitor for policy changes")

        return actions
