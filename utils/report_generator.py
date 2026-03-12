from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors


def generate_report(data, filepath):

    styles = getSampleStyleSheet()
    elements = []

    # Title
    elements.append(Paragraph("Cloud Security Policy Analyzer Report", styles['Title']))
    elements.append(Spacer(1, 20))

    # Scores
    elements.append(Paragraph(f"Risk Score: {data.get('risk_score', 0)}", styles['Normal']))
    elements.append(Paragraph(f"Security Score: {data.get('security_score', 0)}", styles['Normal']))
    elements.append(Spacer(1, 20))

    # Issues table
    elements.append(Paragraph("Detected Security Issues", styles['Heading2']))
    elements.append(Spacer(1, 10))

    table_data = [["Risk", "Problem", "Reason"]]

    for issue in data.get("issues", []):
        table_data.append([
            str(issue.get("risk", "")),
            str(issue.get("problem", "")),
            str(issue.get("reason", ""))
        ])

    table = Table(table_data)

    table.setStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 1, colors.black)
    ])

    elements.append(table)
    elements.append(Spacer(1, 20))

    # Recommendations
    elements.append(Paragraph("Recommendations", styles['Heading2']))
    elements.append(Spacer(1, 10))

    for rec in data.get("recommendations", []):
        elements.append(Paragraph(f"• {rec}", styles['Normal']))

    pdf = SimpleDocTemplate(filepath, pagesize=A4)
    pdf.build(elements)