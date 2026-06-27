import os
from datetime import datetime
import json
from io import BytesIO

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to add 'Page X of Y' footer and header decorations.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_elements(num_pages)
            super().showPage()
        super().save()

    def draw_page_elements(self, page_count):
        self.saveState()
        
        navy = colors.HexColor('#0F172A')
        muted_gray = colors.HexColor('#64748B')
        
        # Header (Only on page 2 and later)
        if self._pageNumber > 1:
            self.setFont("Helvetica-Bold", 8)
            self.setFillColor(navy)
            self.drawString(54, 750, "APK SENTINEL AI - threat intelligence report")
            
            self.setStrokeColor(colors.HexColor('#CBD5E1'))
            self.setLineWidth(0.5)
            self.line(54, 742, 558, 742)
            
        # Footer on all pages
        self.setFont("Helvetica", 8)
        self.setFillColor(muted_gray)
        self.drawString(54, 36, "CONFIDENTIAL - INTERNAL SOC USE ONLY")
        
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 36, page_text)
        
        self.restoreState()


def sanitize_value(val):
    if isinstance(val, str):
        return val.encode("ascii", errors="ignore").decode()
    elif isinstance(val, dict):
        return {k: sanitize_value(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [sanitize_value(v) for v in val]
    return val


class PDFReportGenerator:
    @staticmethod
    def generate(
        metadata: dict, 
        features: dict, 
        risk: dict, 
        threat: dict, 
        mitre: list[dict], 
        families: list[dict],
        ai_report: dict,
        output_stream=None
    ) -> BytesIO:
        # Sanitize all inputs to prevent Unicode/Emoji crashes in ReportLab
        metadata = sanitize_value(metadata)
        features = sanitize_value(features)
        risk = sanitize_value(risk)
        threat = sanitize_value(threat)
        mitre = sanitize_value(mitre)
        families = sanitize_value(families)
        ai_report = sanitize_value(ai_report)

        if output_stream is None:
            output_stream = BytesIO()

        # Page setup
        doc = SimpleDocTemplate(
            output_stream,
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54
        )

        styles = getSampleStyleSheet()
        
        primary_color = colors.HexColor('#0F172A')
        secondary_color = colors.HexColor('#2563EB')
        text_color = colors.HexColor('#334155')
        
        # Define verdicts colors
        verdict = risk.get("verdict", "Safe")
        if verdict in ("Critical", "malware"):
            verdict_color = colors.HexColor('#991B1B')
            verdict_bg = colors.HexColor('#FEE2E2')
        elif verdict == "High Risk":
            verdict_color = colors.HexColor('#C2410C')
            verdict_bg = colors.HexColor('#FFEDD5')
        elif verdict == "Suspicious":
            verdict_color = colors.HexColor('#854D0E')
            verdict_bg = colors.HexColor('#FEF9C3')
        else:
            verdict_color = colors.HexColor('#166534')
            verdict_bg = colors.HexColor('#DCFCE7')

        # Paragraph Styles
        title_style = ParagraphStyle(
            'DocTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=22,
            leading=26,
            textColor=primary_color,
            spaceAfter=10
        )
        
        h1_style = ParagraphStyle(
            'SectionHeader',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=13,
            leading=16,
            textColor=secondary_color,
            spaceBefore=14,
            spaceAfter=6,
            keepWithNext=True
        )

        body_style = ParagraphStyle(
            'ReportBody',
            parent=styles['BodyText'],
            fontName='Helvetica',
            fontSize=9.5,
            leading=13.5,
            textColor=text_color,
            spaceAfter=6
        )
        
        bold_body_style = ParagraphStyle(
            'ReportBodyBold',
            parent=body_style,
            fontName='Helvetica-Bold'
        )

        meta_label_style = ParagraphStyle(
            'MetaLabel',
            parent=body_style,
            fontName='Helvetica-Bold',
            fontSize=8.5,
            leading=11.5,
            textColor=colors.HexColor('#475569')
        )
        
        meta_val_style = ParagraphStyle(
            'MetaVal',
            parent=body_style,
            fontName='Helvetica-Oblique',
            fontSize=8.5,
            leading=11.5,
            textColor=text_color
        )

        story = []

        # --- TITLE BLOCK ---
        story.append(Spacer(1, 10))
        story.append(Paragraph("APK SENTINEL AI", title_style))
        story.append(Paragraph("Automated Malware Intelligence & Risk Assessment Report", ParagraphStyle('SubTitle', fontName='Helvetica', fontSize=11, leading=14, textColor=colors.HexColor('#4B5563'), spaceAfter=10)))
        story.append(Spacer(1, 5))

        # --- EXECUTIVE SOC SUMMARY BANNER ---
        top_family = families[0]["family_name"] if families else "Generic"
        top_category = families[0]["threat_category"] if families else "Malicious"
        recs_clean = ai_report.get("recommendations", "Isolate device.").split("\n")[0]

        summary_banner_data = [
            [Paragraph("<b>THREAT LEVEL:</b>", meta_label_style), Paragraph(f"<font color='{verdict_color.hexval()}'><b>{verdict.upper()}</b></font>", bold_body_style),
             Paragraph("<b>THREAT CATEGORY:</b>", meta_label_style), Paragraph(top_category, body_style)],
            [Paragraph("<b>MALWARE FAMILY:</b>", meta_label_style), Paragraph(top_family, body_style),
             Paragraph("<b>RECOMMENDED ACTION:</b>", meta_label_style), Paragraph(recs_clean, ParagraphStyle('BannerRec', parent=body_style, fontSize=8.5, leading=11, textColor=colors.HexColor('#B91C1C'), fontName='Helvetica-Bold'))]
        ]
        summary_banner_table = Table(summary_banner_data, colWidths=[100, 150, 110, 140])
        summary_banner_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#E2E8F0')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor('#F1F5F9'))
        ]))
        story.append(summary_banner_table)
        story.append(Spacer(1, 10))

        # --- METADATA & RISK SCORE BANNER ---
        risk_score_text = f"<font size='32'><b>{risk.get('risk_score'):.0f}</b></font><font size='12'>/100</font><br/><font size='10'><b>{verdict.upper()}</b></font>"
        
        meta_table_data = [
            [Paragraph("File Name", meta_label_style), Paragraph(metadata.get("file_name", "N/A"), meta_val_style), 
             Paragraph(risk_score_text, ParagraphStyle('RiskCallout', fontName='Helvetica', alignment=1, textColor=verdict_color, leading=16))],
            [Paragraph("Package Name", meta_label_style), Paragraph(metadata.get("package_name", "N/A"), meta_val_style), ""],
            [Paragraph("SHA-256", meta_label_style), Paragraph(metadata.get("sha256", "N/A"), meta_val_style), ""],
            [Paragraph("File Size", meta_label_style), Paragraph(f"{metadata.get('file_size', 0) / (1024*1024):.2f} MB", meta_val_style), ""],
            [Paragraph("Version", meta_label_style), Paragraph(f"{features.get('version_name', '1.0')} (Code: {features.get('version_code', '1')})", meta_val_style), ""],
            [Paragraph("Report Time", meta_label_style), Paragraph(datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"), meta_val_style), ""]
        ]

        meta_table = Table(meta_table_data, colWidths=[90, 260, 150])
        meta_table.setStyle(TableStyle([
            ('SPAN', (2, 0), (2, 5)), 
            ('BACKGROUND', (2, 0), (2, 5), verdict_bg),
            ('ALIGN', (2, 0), (2, 5), 'CENTER'),
            ('VALIGN', (2, 0), (2, 5), 'MIDDLE'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
            ('LINEBELOW', (0, 0), (1, -2), 0.5, colors.HexColor('#E2E8F0')),
            ('BOX', (2, 0), (2, 5), 1.5, verdict_color),
        ]))
        
        story.append(meta_table)
        story.append(Spacer(1, 10))

        # --- SECTION: SECURITY SCORE BREAKDOWN ---
        story.append(Paragraph("Security Score Breakdown (Balanced 4-factor Metric)", h1_style))
        breakdown = risk.get("breakdown", {})
        
        breakdown_data = [
            [Paragraph("<b>Evaluation Category</b>", meta_label_style), Paragraph("<b>Metric Value</b>", meta_label_style), Paragraph("<b>Weighted Risk Score Contribution (25% each)</b>", meta_label_style)],
            [Paragraph("Permission Risks", body_style), Paragraph(f"{breakdown.get('permission_risk_score', 0.0):.1f} / 100", body_style), Paragraph(f"{breakdown.get('permission_risk_score', 0.0) * 0.25:.1f} / 25", bold_body_style)],
            [Paragraph("Outbound Network Risks", body_style), Paragraph(f"{breakdown.get('threat_intel_score', 0.0):.1f} / 100", body_style), Paragraph(f"{breakdown.get('threat_intel_score', 0.0) * 0.25:.1f} / 25", bold_body_style)],
            [Paragraph("Obfuscation & Evasion Risks", body_style), Paragraph(f"{breakdown.get('obfuscation_risk_score', 0.0):.1f} / 100", body_style), Paragraph(f"{breakdown.get('obfuscation_risk_score', 0.0) * 0.25:.1f} / 25", bold_body_style)],
            [Paragraph("Behavior & ATT&CK Severity", body_style), Paragraph(f"{breakdown.get('mitre_severity_score', 0.0):.1f} / 100", body_style), Paragraph(f"{breakdown.get('mitre_severity_score', 0.0) * 0.25:.1f} / 25", bold_body_style)],
            [Paragraph("<b>Final Risk Score</b>", meta_label_style), "", Paragraph(f"<b>{risk.get('risk_score', 0.0):.1f} / 100</b>", ParagraphStyle('FinalRisk', parent=meta_label_style, textColor=verdict_color, fontSize=10))]
        ]
        breakdown_table = Table(breakdown_data, colWidths=[200, 140, 160])
        breakdown_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F8FAFC')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('SPAN', (0, 5), (1, 5)),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(breakdown_table)
        story.append(Spacer(1, 10))

        # --- SECTION: EXECUTIVE SUMMARY ---
        story.append(Paragraph("Executive Summary", h1_style))
        story.append(Paragraph(ai_report.get("executive_summary", "No summary provided."), body_style))
        story.append(Spacer(1, 10))

        story.append(PageBreak())

        # --- SECTION: ATTACK CHAIN VISUALIZATION ---
        story.append(Paragraph("Attack Chain Flowchart", h1_style))
        chain = features.get("attack_chain", [])
        if not chain:
            chain = ["APK Installed", "Loads Telemetry Services", "No Hostile Actions Triggered"]
        
        # Format chain items horizontally as blocks
        chain_blocks = []
        for idx, step in enumerate(chain):
            step_style = ParagraphStyle(
                'ChainStep', 
                fontName='Helvetica-Bold', 
                fontSize=8, 
                alignment=1, 
                textColor=colors.HexColor('#1E293B')
            )
            arrow_style = ParagraphStyle(
                'ChainArrow', 
                fontName='Helvetica-Bold', 
                fontSize=12, 
                alignment=1, 
                textColor=secondary_color
            )
            
            chain_blocks.append(Paragraph(f"<b>STEP {idx+1}</b><br/>{step}", step_style))
            if idx < len(chain) - 1:
                chain_blocks.append(Paragraph("→", arrow_style))

        # Dynamic widths
        widths = []
        row_content = []
        for idx in range(len(chain_blocks)):
            if idx % 2 == 1:
                widths.append(20) # Arrow width
            else:
                widths.append(85) # Block width
            row_content.append(chain_blocks[idx])

        # If too long, split into two rows to prevent page overflow
        if len(widths) > 7:
            row1_w = widths[:7]
            row1_c = row_content[:7]
            
            row2_w = widths[7:]
            row2_c = row_content[7:]
            
            t1 = Table([row1_c], colWidths=row1_w)
            t1.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#EFF6FF')),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#BFDBFE')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(t1)
            story.append(Spacer(1, 4))
            
            # Remove leading arrow from second row if present
            t2 = Table([row2_c], colWidths=row2_w)
            t2.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#EFF6FF')),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#BFDBFE')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(t2)
        else:
            t = Table([row_content], colWidths=widths)
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#EFF6FF')),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#BFDBFE')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(t)
        story.append(Spacer(1, 10))

        # --- SECTION: MALWARE FAMILY SIMILARITY ---
        story.append(Paragraph("Malware Family Attribution & Evidence", h1_style))
        top_family_dict = families[0] if families else None
        evidence_list = []
        if top_family_dict:
            family_name = top_family_dict.get("family_name", "").lower()
            perms = features.get("permissions", [])
            methods = features.get("methods", [])
            urls = features.get("urls", [])
            
            # Check Banking Trojan heuristics
            if "bank" in family_name or "anubis" in family_name or "cerberus" in family_name:
                if any("read_sms" in p.lower() or "receive_sms" in p.lower() for p in perms):
                    evidence_list.append("SMS Interception Capability (READ_SMS / RECEIVE_SMS)")
                if "android.permission.SYSTEM_ALERT_WINDOW" in perms:
                    evidence_list.append("Overlay Draw Capability (SYSTEM_ALERT_WINDOW)")
                if "android.permission.BIND_ACCESSIBILITY_SERVICE" in perms:
                    evidence_list.append("Accessibility Abuse Capability (BIND_ACCESSIBILITY_SERVICE)")
            
            # Check Spyware heuristics
            elif "spy" in family_name or "joker" in family_name:
                if any("location" in p.lower() for p in perms):
                    evidence_list.append("Precise Location Access")
                if "android.permission.CAMERA" in perms:
                    evidence_list.append("Camera Access")
                if "android.permission.RECORD_AUDIO" in perms:
                    evidence_list.append("Stealth Audio Recording")
            
            # Check RAT heuristics
            elif "rat" in family_name or "remote" in family_name:
                if urls or any("194." in u or "c2" in u for u in urls):
                    evidence_list.append("Remote Command & Control (C2) Connections")
                if features.get("services") or any("service" in m.lower() for m in methods):
                    evidence_list.append("Evasive Background Services")
            
            att_data = [
                [Paragraph("<b>ATTRIBUTED MALWARE FAMILY:</b>", meta_label_style), Paragraph(top_family_dict.get("family_name", "N/A"), bold_body_style)],
                [Paragraph("<b>CONFIDENCE RATING:</b>", meta_label_style), Paragraph(f"{top_family_dict.get('similarity_score', 0.0):.0f}% ({top_family_dict.get('confidence', 'LOW')})", bold_body_style)],
            ]
            if evidence_list:
                bullets = "<br/>".join([f"• {ev}" for ev in evidence_list])
                att_data.append([Paragraph("<b>SUPPORTING EVIDENCE:</b>", meta_label_style), Paragraph(bullets, body_style)])
            else:
                att_data.append([Paragraph("<b>SUPPORTING EVIDENCE:</b>", meta_label_style), Paragraph("Heuristic rules matched structural bytecode template.", body_style)])
            
            att_table = Table(att_data, colWidths=[180, 320])
            att_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#CBD5E1')),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.HexColor('#E2E8F0'))
            ]))
            story.append(att_table)
        else:
            story.append(Paragraph("Attribution models found no significant similarities to active malware families.", body_style))
        story.append(Spacer(1, 10))

        # --- SECTION: THREAT INTELLIGENCE AND BEHAVIORS ---
        story.append(Paragraph("Static Threat Intelligence Indicators", h1_style))
        inds = threat.get("indicators", [])
        if inds:
            threat_table_data = [[
                Paragraph("<b>Indicator Flagged</b>", meta_label_style),
                Paragraph("<b>Threat Type</b>", meta_label_style),
                Paragraph("<b>Severity</b>", meta_label_style)
            ]]
            for ind in inds[:6]:
                sev_str = ind.get("severity", "LOW")
                sev_color = colors.HexColor('#B91C1C') if sev_str in ("CRITICAL", "HIGH") else (colors.HexColor('#D97706') if sev_str == "MEDIUM" else colors.HexColor('#16A34A'))
                threat_table_data.append([
                    Paragraph(ind.get("indicator", "N/A"), body_style),
                    Paragraph(ind.get("type", "N/A"), body_style),
                    Paragraph(f"<b>{sev_str}</b>", ParagraphStyle('SevText', parent=body_style, textColor=sev_color))
                ])
            
            threat_table = Table(threat_table_data, colWidths=[290, 120, 90])
            threat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F8FAFC')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(threat_table)
        else:
            story.append(Paragraph("No threat indicators flagged.", body_style))
        
        story.append(Spacer(1, 10))

        # --- SECTION: STATIC ANALYSIS DETAILED METADATA ---
        story.append(Paragraph("Decompiled Artifacts & Integrity Checks", h1_style))
        native_libs = features.get("cert_metadata", {}).get("native_libraries", [])
        exported_comps = features.get("cert_metadata", {}).get("exported_components", [])
        hardcoded_keys = features.get("cert_metadata", {}).get("hardcoded_credentials", [])
        dex_ent = features.get("cert_metadata", {}).get("dex_entropies", [])

        # Render DEX Section Entropies
        if dex_ent:
            story.append(Paragraph("<b>DEX File Entropies (Integrity Verification)</b>", bold_body_style))
            ent_data = [[Paragraph("<b>DEX File</b>", meta_label_style), Paragraph("<b>Shannon Entropy</b>", meta_label_style), Paragraph("<b>Verdict</b>", meta_label_style)]]
            for de in dex_ent[:4]:
                ent_color = colors.HexColor('#B91C1C') if de.get("verdict") == "Packed/Obfuscated" else colors.HexColor('#16A34A')
                ent_data.append([
                    Paragraph(de.get("section", "N/A"), body_style),
                    Paragraph(de.get("value", "N/A"), body_style),
                    Paragraph(f"<b>{de.get('verdict')}</b>", ParagraphStyle('EntText', parent=body_style, textColor=ent_color))
                ])
            ent_table = Table(ent_data, colWidths=[200, 150, 150])
            ent_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F8FAFC')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
            ]))
            story.append(ent_table)
            story.append(Spacer(1, 8))

        # Render Exported Components
        if exported_comps:
            story.append(Paragraph("<b>Exported Android Components (Attack Surface Mapping)</b>", bold_body_style))
            comp_data = [[Paragraph("<b>Component Path / Name</b>", meta_label_style), Paragraph("<b>Component Type</b>", meta_label_style)]]
            for ec in exported_comps[:5]:
                comp_data.append([
                    Paragraph(ec.get("name", "N/A"), ParagraphStyle('CompPath', parent=body_style, fontName='Courier', fontSize=7.5)),
                    Paragraph(ec.get("type", "N/A"), body_style)
                ])
            comp_table = Table(comp_data, colWidths=[380, 120])
            comp_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F8FAFC')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
            ]))
            story.append(comp_table)
            story.append(Spacer(1, 8))

        # Render Hardcoded Keys
        if hardcoded_keys:
            story.append(Paragraph("<b>Hardcoded API Keys & Redacted Secrets</b>", bold_body_style))
            key_data = [[Paragraph("<b>Secret Indicator Type</b>", meta_label_style), Paragraph("<b>Redacted Hex / Assignment Value</b>", meta_label_style)]]
            for hk in hardcoded_keys[:5]:
                key_data.append([
                    Paragraph(hk.get("type", "N/A"), body_style),
                    Paragraph(hk.get("raw", "N/A"), ParagraphStyle('KeyRaw', parent=body_style, fontName='Courier', fontSize=7.5, textColor=colors.HexColor('#B91C1C')))
                ])
            key_table = Table(key_data, colWidths=[200, 300])
            key_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F8FAFC')),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
                ('TOPPADDING', (0, 0), (-1, -1), 3),
            ]))
            story.append(key_table)
            story.append(Spacer(1, 8))

        # Render Native Libraries
        if native_libs:
            story.append(Paragraph("<b>Extracted Native Shared Objects (.so Libraries)</b>", bold_body_style))
            libs_str = ", ".join([os.path.basename(nl) for nl in native_libs[:12]])
            story.append(Paragraph(libs_str, ParagraphStyle('LibsText', parent=body_style, fontName='Courier', fontSize=8, textColor=colors.HexColor('#1E293B'))))
        
        story.append(Spacer(1, 10))

        # --- SECTION: MITRE ATT&CK MAPPING ---
        story.append(Paragraph("MITRE ATT&CK Mobile Technique Mapping", h1_style))
        
        TECHNIQUE_TO_TACTIC = {
            "T1477": "Initial Access",
            "T1624": "Persistence",
            "T1546": "Persistence",
            "T1516": "Credential Access",
            "T1411": "Credential Access",
            "T1414": "Credential Access",
            "T1636": "Collection",
            "T1412": "Collection",
            "T1429": "Collection",
            "T1512": "Collection",
            "T1430": "Discovery",
            "T1404": "Discovery",
            "T1426": "Discovery",
            "T1407": "Defense Evasion",
            "T1409": "Defense Evasion"
        }
        
        if mitre:
            mitre_by_tactic = {}
            for m_item in mitre:
                tech_id = m_item.get("technique_id", "")
                tactic = TECHNIQUE_TO_TACTIC.get(tech_id, "Discovery")
                if tactic not in mitre_by_tactic:
                    mitre_by_tactic[tactic] = []
                mitre_by_tactic[tactic].append(m_item)
                
            for tactic, items in mitre_by_tactic.items():
                story.append(Paragraph(f"<b>{tactic}</b>", ParagraphStyle('TacticHeader', parent=h1_style, fontSize=11, spaceBefore=8, spaceAfter=4, textColor=colors.HexColor('#0F172A'), keepWithNext=True)))
                for item in items:
                    sev_str = item.get("severity", "LOW")
                    sev_color_hex = '#B91C1C' if sev_str in ("CRITICAL", "HIGH") else ('#D97706' if sev_str == "MEDIUM" else '#16A34A')
                    evidence_str = item.get("evidence", "No specific evidence.")
                    story.append(Paragraph(f"• <b>{item.get('technique_id')} - {item.get('technique_name')}</b> [<font color='{sev_color_hex}'><b>{sev_str}</b></font>]: {evidence_str}", ParagraphStyle('TechDetail', parent=body_style, leftIndent=15)))
                story.append(Spacer(1, 4))
        else:
            story.append(Paragraph("No MITRE ATT&CK Mobile techniques mapped.", body_style))

        story.append(PageBreak())

        # --- SECTION: AI SECURITY ANALYSIS ---
        story.append(Paragraph("Groq SecOps Intelligence Report", h1_style))
        
        story.append(Paragraph("<b>Detailed Threat Assessment:</b>", bold_body_style))
        story.append(Paragraph(ai_report.get("threat_assessment", "N/A"), body_style))
        story.append(Spacer(1, 6))

        story.append(Paragraph("<b>Malware Family Attribution & Heuristics:</b>", bold_body_style))
        story.append(Paragraph(ai_report.get("malware_family_analysis", "N/A"), body_style))
        story.append(Spacer(1, 6))

        story.append(Paragraph("<b>MITRE ATT&CK Capability Assessment:</b>", bold_body_style))
        story.append(Paragraph(ai_report.get("mitre_analysis", "N/A"), body_style))
        story.append(Spacer(1, 6))

        story.append(Paragraph("<b>Scoring Justification:</b>", bold_body_style))
        story.append(Paragraph(ai_report.get("risk_justification", "N/A"), body_style))
        story.append(Spacer(1, 6))

        story.append(Paragraph("<b>Indicators of Compromise (IOCs):</b>", bold_body_style))
        raw_ioc = ai_report.get("ioc", "[]")
        try:
            ioc_list = json.loads(raw_ioc)
            if isinstance(ioc_list, list):
                ioc_text = ", ".join(ioc_list)
            else:
                ioc_text = str(raw_ioc)
        except Exception:
            ioc_text = str(raw_ioc)
        story.append(Paragraph(ioc_text, ParagraphStyle('IOCText', parent=body_style, fontName='Courier', fontSize=8.5)))
        story.append(Spacer(1, 6))

        story.append(Paragraph("<b>Incident Action Recommendations:</b>", bold_body_style))
        recs_text = ai_report.get("recommendations", "").replace("\n", "<br/>")
        story.append(Paragraph(recs_text, body_style))
        story.append(Spacer(1, 6))

        story.append(Paragraph("<b>SOC Analyst commentary:</b>", bold_body_style))
        story.append(Paragraph(ai_report.get("soc_commentary", "N/A"), ParagraphStyle('CommentaryText', parent=body_style, fontName='Helvetica-Oblique', textColor=colors.HexColor('#1E293B'))))
        
        # Build Document
        doc.build(story, canvasmaker=NumberedCanvas)
        output_stream.seek(0)
        return output_stream
