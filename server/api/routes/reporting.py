import io
from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
# import matplotlib.pyplot as plt # Skipped to avoid heavy backend deps for demo purposes, 
#                                 # but left in requirements if advanced charts are needed later
from datetime import datetime

router = APIRouter()

def build_pdf_document():
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    
    # Custom Title Style
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#0ea5e9') # SecureWatch Accent Color
    )
    
    Story = []
    
    # Title
    Story.append(Paragraph("SecureWatch Executive Security Report", title_style))
    Story.append(Spacer(1, 12))
    
    # Date
    date_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    Story.append(Paragraph(f"Generated At: {date_str}", styles["Normal"]))
    Story.append(Spacer(1, 24))
    
    # Executive Summary
    Story.append(Paragraph("Executive Summary", styles["Heading2"]))
    exec_summary = """
    This report outlines the current security posture of the infrastructure monitored by SecureWatch.
    It includes active critical alerts, endpoint software vulnerability summaries, and regulatory compliance posture.
    Please review the identified Critical events for immediate remediation.
    """
    Story.append(Paragraph(exec_summary, styles["Normal"]))
    Story.append(Spacer(1, 24))
    
    # Compliance Posture
    Story.append(Paragraph("Global Regulatory Compliance Posture", styles["Heading2"]))
    
    # Mock data for the report
    compliance_data = [
        ["Framework", "Status", "Violations", "Grade"],
        ["PCI DSS 4.0", "Warning", "14", "82%"],
        ["NIST 800-53", "Healthy", "6", "90%"],
        ["CIS Controls v8", "Critical", "24", "65%"]
    ]
    
    t_comp = Table(compliance_data, colWidths=[150, 100, 100, 100])
    t_comp.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,0), 12),
        ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#1e293b')),
        ('TEXTCOLOR', (0,1), (-1,-1), colors.whitesmoke),
        ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#334155'))
    ]))
    
    Story.append(t_comp)
    Story.append(Spacer(1, 24))

    # Vulnerabilities 
    Story.append(Paragraph("Top Critical Vulnerabilities", styles["Heading2"]))
    
    vuln_data = [
        ["Host", "Package / Software", "CVE / Priority", "Fix Version"],
        ["linux-prod-web1", "bash 4.2-2", "Critical (CVSS 9.8)", "4.3-1"],
        ["linux-prod-web1", "openssl 1.0.1", "High (CVSS 7.5)", "1.0.1g"],
        ["win-desktop-04", "Microsoft Office", "High", "Patch Tuesday Build"]
    ]
    
    t_vuln = Table(vuln_data, colWidths=[100, 150, 120, 100])
    t_vuln.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0,0), (-1,0), 12),
        ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#1e293b')),
        ('TEXTCOLOR', (0,1), (-1,-1), colors.whitesmoke),
        ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#334155'))
    ]))
    
    Story.append(t_vuln)
    Story.append(Spacer(1, 24))
    
    # Footer
    Story.append(Paragraph("End of Report", styles["Heading3"]))
    
    doc.build(Story)
    buffer.seek(0)
    return buffer

@router.get("/generate", response_class=StreamingResponse)
async def generate_executive_report():
    pdf_buffer = build_pdf_document()
    return StreamingResponse(
        pdf_buffer, 
        media_type="application/pdf", 
        headers={"Content-Disposition": f"attachment; filename=SecureWatch_Report_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.pdf"}
    )
