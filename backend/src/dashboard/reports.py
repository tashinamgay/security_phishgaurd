# backend/src/dashboard/reports.py
# Generates PDF and CSV export reports
# Member: Aditi (Frontend & DevOps Lead)
#
# SIMPLE EXPLANATION:
# After analysis users can download reports
# PDF  - professional formatted report using ReportLab library
# CSV  - spreadsheet with all analyses for data review
#
# HOW TO USE:
# PDF: click "Download PDF" on results page
# CSV: click "Export CSV" on dashboard

import csv, io
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet


def generate_pdf(record):
    """
    Generate PDF report for one email analysis.
    Returns PDF as bytes for browser download.
    """
    buf    = io.BytesIO()
    doc    = SimpleDocTemplate(buf, pagesize=A4,
                               rightMargin=45, leftMargin=45,
                               topMargin=45, bottomMargin=45)
    styles = getSampleStyleSheet()
    story  = []

    # Title
    story.append(Paragraph('PhishGuard — Email Analysis Report', styles['Title']))
    story.append(Spacer(1, 10))

    # Risk level with colour
    clr = {'RED': colors.red, 'YELLOW': colors.orange, 'GREEN': colors.green
           }.get(record.get('risk_level'), colors.black)
    story.append(Paragraph(
        f'<b>Risk Level: <font color="{clr}">{record.get("risk_level","N/A")}</font></b> '
        f'| Score: {record.get("risk_score", 0)}/100',
        styles['Heading2']))
    story.append(Spacer(1, 10))

    # Email details table
    data = [
        ['Subject',         record.get('email_subject', 'N/A')],
        ['Sender',          record.get('email_sender', 'N/A')],
        ['Analysed At',     str(record.get('analysed_at', 'N/A'))],
        ['Quarantined',     'Yes' if record.get('is_quarantined') else 'No'],
        ['Total URLs',      str(record.get('url_count', 0))],
        ['Suspicious URLs', str(record.get('suspicious_url_count', 0))],
        ['Attachments',     str(record.get('attachment_count', 0))],
    ]
    t = Table(data, colWidths=[140, 360])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#1e293b')),
        ('TEXTCOLOR',  (0, 0), (0, -1), colors.white),
        ('FONTNAME',   (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE',   (0, 0), (-1, -1), 9),
        ('GRID',       (0, 0), (-1, -1), 0.4, colors.grey),
        ('PADDING',    (0, 0), (-1, -1), 7),
    ]))
    story.append(t)
    story.append(Spacer(1, 16))

    # AI Explanation section
    ai_exp = record.get('ai_explanation')
    if ai_exp:
        story.append(Paragraph('AI Explanation:', styles['Heading3']))
        story.append(Spacer(1, 4))
        story.append(Paragraph(ai_exp, styles['Normal']))
        story.append(Spacer(1, 14))

    # Detection findings list
    story.append(Paragraph('Detection Findings:', styles['Heading3']))
    story.append(Spacer(1, 6))
    reasons = record.get('reasons', [])
    if reasons:
        for r in reasons:
            story.append(Paragraph(f'• {r}', styles['Normal']))
            story.append(Spacer(1, 3))
    else:
        story.append(Paragraph('No suspicious indicators detected.', styles['Normal']))

    doc.build(story)
    buf.seek(0)
    return buf.read()


def generate_csv(analyses):
    """
    Generate CSV file with all analyses.
    Returns CSV string for browser download.
    """
    out = io.StringIO()
    w   = csv.writer(out)

    # Header row
    w.writerow(['ID', 'Subject', 'Sender', 'Risk Level', 'Score',
                'URLs', 'Suspicious URLs', 'Attachments', 'Quarantined', 'Analysed At'])

    # One row per analysis
    for a in analyses:
        w.writerow([
            str(a.get('_id', '')),
            a.get('email_subject', ''),
            a.get('email_sender', ''),
            a.get('risk_level', ''),
            a.get('risk_score', 0),
            a.get('url_count', 0),
            a.get('suspicious_url_count', 0),
            a.get('attachment_count', 0),
            'Yes' if a.get('is_quarantined') else 'No',
            str(a.get('analysed_at', '')),
        ])

    return out.getvalue()
