from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors


def generate_report(data, filepath):

    styles = getSampleStyleSheet()
    elements = []

    # ===== TITLE =====
    elements.append(Paragraph("Cloud Security Policy Analyzer Report", styles['Title']))
    elements.append(Spacer(1, 20))

    # ===== SUMMARY SECTION =====
    risk_score = data.get("risk_score", 0)
    security_score = data.get("security_score", 0)

    # Risk Level
    if risk_score <= 30:
        risk_level = "LOW"
        risk_color = colors.green
    elif risk_score <= 70:
        risk_level = "MEDIUM"
        risk_color = colors.orange
    else:
        risk_level = "HIGH"
        risk_color = colors.red

    elements.append(Paragraph("<b>Summary</b>", styles['Heading2']))
    elements.append(Spacer(1, 10))

    elements.append(Paragraph(f"Risk Score: {risk_score}", styles['Normal']))
    elements.append(Paragraph(f"Security Score: {security_score}", styles['Normal']))
    elements.append(Paragraph(f"Risk Level: <font color='{risk_color}'>{risk_level}</font>", styles['Normal']))

    elements.append(Spacer(1, 20))

    # ===== AI SUMMARY =====
    ai_summary = data.get("ai_summary", "")
    if ai_summary:
        elements.append(Paragraph("AI Analysis Summary", styles['Heading2']))
        elements.append(Spacer(1, 10))
        elements.append(Paragraph(ai_summary, styles['Normal']))
        elements.append(Spacer(1, 20))

    # ===== ISSUES TABLE =====
    elements.append(Paragraph("Detected Security Issues", styles['Heading2']))
    elements.append(Spacer(1, 10))

    table_data = [["Risk", "Problem", "Reason"]]

    for issue in data.get("issues", []):
        table_data.append([
            str(issue.get("risk", "")),
            str(issue.get("problem", "")),
            str(issue.get("reason", ""))
        ])

    table = Table(table_data, repeatRows=1)

    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 1, colors.black),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ]))

    elements.append(table)
    elements.append(Spacer(1, 20))

    # ===== ATTACK PATHS =====
    attack_paths = data.get("attack_paths", [])
    if attack_paths:
        elements.append(Paragraph("Attack Path Analysis", styles['Heading2']))
        elements.append(Spacer(1, 10))

        for path in attack_paths:
            elements.append(Paragraph(" → ".join(path), styles['Normal']))

        elements.append(Spacer(1, 20))

    # ===== RECOMMENDATIONS =====
    elements.append(Paragraph("Recommendations", styles['Heading2']))
    elements.append(Spacer(1, 10))

    for rec in data.get("recommendations", []):
        elements.append(Paragraph(f"• {rec}", styles['Normal']))

    elements.append(Spacer(1, 20))

    # ===== CONCLUSION =====
    elements.append(Paragraph("Conclusion", styles['Heading2']))
    elements.append(Spacer(1, 10))

    if risk_level == "HIGH":
        conclusion = "The system is at high risk and requires immediate security improvements."
    elif risk_level == "MEDIUM":
        conclusion = "The system has moderate security risks and should be reviewed."
    else:
        conclusion = "The system is relatively secure with minor improvements needed."

    elements.append(Paragraph(conclusion, styles['Normal']))

    # ===== BUILD PDF =====
    pdf = SimpleDocTemplate(filepath, pagesize=A4)
    pdf.build(elements)