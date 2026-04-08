"""PDF report generator for VAPT Dashboard using ReportLab."""

import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable,
    PageBreak, KeepTogether,
)


# ── Severity helpers ──────────────────────────────────────────────────────────

_SEV_COLORS = {
    "critical": colors.HexColor("#dc2626"),
    "high":     colors.HexColor("#ea580c"),
    "medium":   colors.HexColor("#ca8a04"),
    "low":      colors.HexColor("#2563eb"),
    "info":     colors.HexColor("#6b7280"),
}

def _severity_color(severity: str) -> colors.Color:
    return _SEV_COLORS.get(severity, colors.black)


# ── Recommendation mapping ────────────────────────────────────────────────────

_VULN_RECOMMENDATIONS = [
    ("openssh", [
        "Update OpenSSH to the latest secure version and disable weak algorithms.",
        "Ensure secure key exchange algorithms such as curve25519-sha256 are used.",
        "Disable password-based authentication in favor of key-based authentication.",
    ]),
    ("terrapin", [
        "Upgrade OpenSSH to version 9.6 or later which mitigates the Terrapin attack.",
        "Disable the chacha20-poly1305@openssh.com cipher and -etm@openssh.com MAC algorithms.",
    ]),
    ("apache", [
        "Upgrade Apache HTTP Server to the latest stable release.",
        "Disable directory listing (Options -Indexes).",
        "Remove default server response headers using the ServerTokens and ServerSignature directives.",
    ]),
    ("nginx", [
        "Update Nginx to the latest stable version.",
        "Disable server version disclosure (server_tokens off).",
        "Configure appropriate security headers.",
    ]),
    ("security header", [
        "Implement the following security headers:",
        "  - Content-Security-Policy",
        "  - X-Frame-Options: DENY or SAMEORIGIN",
        "  - X-Content-Type-Options: nosniff",
        "  - Strict-Transport-Security (HSTS)",
        "  - Referrer-Policy: strict-origin-when-cross-origin",
    ]),
    ("slowloris", [
        "Configure web server timeout settings to limit slow connections.",
        "Enable rate limiting or deploy a Web Application Firewall (WAF).",
        "Consider using modules like mod_reqtimeout (Apache) or limit_conn (Nginx).",
    ]),
    ("ssh weak", [
        "Disable weak cryptographic algorithms (e.g. diffie-hellman-group1-sha1, 3des-cbc).",
        "Enable strong key exchange methods such as curve25519-sha256 and diffie-hellman-group16-sha512.",
    ]),
    ("ssh diffie-hellman", [
        "Disable Diffie-Hellman moduli smaller than 2048 bits.",
        "Regenerate DH parameters: ssh-keygen -G /tmp/moduli -b 4096 && ssh-keygen -T /etc/ssh/moduli -f /tmp/moduli",
    ]),
    ("ssl", [
        "Disable SSLv3 and TLS 1.0/1.1; enforce TLS 1.2+ only.",
        "Use strong cipher suites and enable Perfect Forward Secrecy (PFS).",
        "Ensure certificates are valid, not expired, and issued by a trusted CA.",
    ]),
    ("tls", [
        "Enforce TLS 1.2 or TLS 1.3 as minimum protocol version.",
        "Disable weak cipher suites and enable AEAD ciphers.",
    ]),
    ("xss", [
        "Sanitize and validate all user inputs on both client and server side.",
        "Implement Content-Security-Policy headers to mitigate XSS attacks.",
        "Use output encoding when rendering user-supplied data.",
    ]),
    ("sql injection", [
        "Use parameterized queries or prepared statements for all database operations.",
        "Implement input validation and enforce least-privilege database accounts.",
    ]),
    ("directory listing", [
        "Disable directory listing on the web server (Options -Indexes for Apache).",
        "Ensure no sensitive files are exposed in web-accessible directories.",
    ]),
    ("waf", [
        "A Web Application Firewall was detected. Review WAF rules for completeness.",
        "Ensure the WAF is configured to block OWASP Top 10 attack patterns.",
    ]),
    ("ftp", [
        "Disable FTP if not required; use SFTP or SCP for secure file transfers.",
        "If FTP is necessary, enforce FTPS (FTP over TLS) and disable anonymous login.",
    ]),
    ("telnet", [
        "Disable Telnet immediately — it transmits credentials in cleartext.",
        "Use SSH as a secure alternative for remote administration.",
    ]),
    ("smb", [
        "Disable SMBv1 and enforce SMBv3 with encryption.",
        "Restrict SMB access to trusted networks using firewall rules.",
    ]),
    ("rdp", [
        "Enable Network Level Authentication (NLA) for RDP.",
        "Restrict RDP access via VPN or firewall rules. Apply all latest patches.",
    ]),
    ("vulners", [
        "Review the CVEs reported by Vulners and apply vendor-supplied patches.",
        "Prioritize patching based on CVSS score and exploitability.",
    ]),
    ("http-title", [
        "Review the web application for information disclosure via page titles.",
    ]),
    ("http-server-header", [
        "Suppress or customize the Server response header to reduce information leakage.",
    ]),
    ("http-favicon", [
        "Review the favicon hash — it may reveal the technology stack to attackers.",
    ]),
    ("password", [
        "Enforce strong password policies (minimum length, complexity, rotation).",
        "Implement multi-factor authentication (MFA) where possible.",
    ]),
    ("ssh-hostkey", [
        "Verify SSH host key fingerprints to prevent man-in-the-middle attacks.",
        "Rotate host keys periodically and ensure keys use strong algorithms (Ed25519 or RSA 4096+).",
    ]),
]

_DEFAULT_RECOMMENDATION = [
    "Review system configuration and apply security best practices for the affected service.",
    "Consult vendor documentation and security advisories for specific remediation guidance.",
]

_SERVICE_RECOMMENDATIONS = [
    ("openssh", "Upgrade OpenSSH to the latest release and apply hardening best practices (e.g., disable root login, use key-based auth)."),
    ("apache", "Upgrade Apache HTTP Server to version 2.4.58 or later and apply security hardening."),
    ("nginx", "Update Nginx to the latest stable version and review configuration for security."),
    ("mysql", "Update MySQL/MariaDB to the latest version. Restrict remote access and enforce strong authentication."),
    ("postgres", "Update PostgreSQL to the latest version. Use SSL connections and restrict network access."),
    ("ftp", "Consider replacing FTP with SFTP. If FTP is required, enforce FTPS."),
    ("telnet", "Disable Telnet and replace with SSH for remote administration."),
    ("redis", "Require authentication on Redis and bind to localhost or trusted interfaces only."),
    ("mongodb", "Enable authentication on MongoDB and restrict network access."),
]


def _get_vuln_recommendation(vuln_name: str) -> list[str]:
    """Return recommendations for a vulnerability based on keyword matching."""
    name_lower = vuln_name.lower()
    for keyword, recs in _VULN_RECOMMENDATIONS:
        if keyword in name_lower:
            return recs
    return _DEFAULT_RECOMMENDATION


def _get_service_recommendation(service_name: str, version: str) -> str | None:
    """Return upgrade recommendation for a known service."""
    svc_lower = (service_name or "").lower() + " " + (version or "").lower()
    for keyword, rec in _SERVICE_RECOMMENDATIONS:
        if keyword in svc_lower:
            return rec
    return None


def build_security_recommendations(vulnerabilities: list, services: list | None = None) -> list[str]:
    """Build a deduplicated set of recommendations from vulnerabilities and services."""
    recommendations: list[str] = []
    seen: set[str] = set()

    for vuln in vulnerabilities or []:
        vuln_name = (vuln.get("vulnerability_name") or vuln.get("title") or "").strip()
        if not vuln_name:
            continue
        for rec in _get_vuln_recommendation(vuln_name):
            if rec not in seen:
                seen.add(rec)
                recommendations.append(rec)

    for service in services or []:
        service_name = service.get("service_name", "")
        version = service.get("version", "")
        rec = _get_service_recommendation(service_name, version)
        if rec and rec not in seen:
            seen.add(rec)
            recommendations.append(rec)

    if not recommendations:
        recommendations.extend(_DEFAULT_RECOMMENDATION)

    return recommendations


# ── Table style presets ───────────────────────────────────────────────────────

_TABLE_HEADER_BG = colors.HexColor("#1e293b")
_TABLE_GRID = colors.HexColor("#cbd5e1")
_TABLE_ALT_ROW = colors.HexColor("#f8fafc")

def _base_table_style():
    return [
        ("BACKGROUND", (0, 0), (-1, 0), _TABLE_HEADER_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME",  (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",  (0, 0), (-1, -1), 9),
        ("GRID",      (0, 0), (-1, -1), 0.5, _TABLE_GRID),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _TABLE_ALT_ROW]),
        ("VALIGN",    (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
    ]


# ── Main report builder ──────────────────────────────────────────────────────

def generate_report(asset: dict, scans: list, ports: list, services: list, vulnerabilities: list) -> bytes:
    """Build a professional VAPT PDF report and return the bytes."""

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        topMargin=25 * mm, bottomMargin=20 * mm,
        leftMargin=20 * mm, rightMargin=20 * mm,
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        "SectionHead", parent=styles["Heading2"],
        textColor=colors.HexColor("#1e293b"),
        spaceAfter=8, spaceBefore=18,
    ))
    styles.add(ParagraphStyle(
        "Meta", parent=styles["Normal"],
        textColor=colors.HexColor("#475569"), fontSize=10,
    ))
    styles.add(ParagraphStyle(
        "RecBullet", parent=styles["Normal"],
        fontSize=9, leftIndent=16, bulletIndent=8,
        textColor=colors.HexColor("#334155"),
    ))
    styles.add(ParagraphStyle(
        "VulnTitle", parent=styles["Normal"],
        fontSize=10, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#1e293b"),
    ))
    styles.add(ParagraphStyle(
        "VulnDetail", parent=styles["Normal"],
        fontSize=9, leftIndent=12,
        textColor=colors.HexColor("#475569"),
    ))

    elements: list = []
    hr = HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"),
                     spaceAfter=10, spaceBefore=6)

    # Count severities upfront
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulnerabilities:
        sev = v.get("severity", "info")
        if sev in sev_counts:
            sev_counts[sev] += 1

    risk_score = asset.get("risk_score", 0)
    if risk_score >= 81:
        risk_label = "Critical"
    elif risk_score >= 51:
        risk_label = "High"
    elif risk_score >= 21:
        risk_label = "Medium"
    else:
        risk_label = "Low"

    # ===== SECTION 1: Scan Summary ============================================
    elements.append(Paragraph("VAPT Scan Report", styles["Title"]))
    elements.append(Spacer(1, 4))
    elements.append(hr)

    latest_scan = scans[0] if scans else {}
    scan_date = latest_scan.get("started_at") or datetime.utcnow()
    if isinstance(scan_date, str):
        scan_date = scan_date[:19]
    else:
        scan_date = scan_date.strftime("%Y-%m-%d %H:%M:%S")

    scan_type = latest_scan.get("scan_type", "N/A")
    scan_status = latest_scan.get("scan_status", "N/A")
    completed_at = latest_scan.get("completed_at")
    if isinstance(completed_at, str):
        completed_at = completed_at[:19]
    elif completed_at:
        completed_at = completed_at.strftime("%Y-%m-%d %H:%M:%S")
    else:
        completed_at = "N/A"

    elements.append(Paragraph("1. Scan Summary", styles["SectionHead"]))
    elements.append(hr)

    scan_summary = [
        ["Field", "Value"],
        ["Scan Type", str(scan_type).capitalize()],
        ["Scan Status", str(scan_status).capitalize()],
        ["Started At", str(scan_date)],
        ["Completed At", str(completed_at)],
        ["Total Ports Scanned", str(len(ports))],
        ["Total Vulnerabilities", str(len(vulnerabilities))],
        ["Risk Level", f"{risk_label} ({risk_score}/100)"],
        ["Report Generated", f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"],
    ]
    t = Table(scan_summary, colWidths=[160, 330])
    t.setStyle(TableStyle(_base_table_style()))
    elements.append(t)
    elements.append(Spacer(1, 14))

    # ===== SECTION 2: Target Information ======================================
    elements.append(Paragraph("2. Target Information", styles["SectionHead"]))
    elements.append(hr)

    asset_data = [
        ["Field", "Value"],
        ["Asset ID", str(asset.get("id", ""))],
        ["Asset Name", str(asset.get("asset_name", ""))],
        ["Asset Type", str(asset.get("asset_type", ""))],
        ["Owner", str(asset.get("owner", "") or "N/A")],
        ["Risk Score", str(risk_score)],
        ["Risk Level", risk_label],
    ]
    t = Table(asset_data, colWidths=[160, 330])
    t.setStyle(TableStyle(_base_table_style()))
    elements.append(t)
    elements.append(Spacer(1, 14))

    # ===== SECTION 3: Open Ports and Services =================================
    elements.append(Paragraph("3. Open Ports and Services", styles["SectionHead"]))
    elements.append(hr)

    # Merge ports and services for a combined view
    svc_by_port = {}
    for s in services:
        port_key = s.get("port", s.get("port_number", ""))
        svc_by_port[str(port_key)] = s

    if ports or services:
        ps_header = ["Port", "Protocol", "State", "Service", "Version"]
        ps_rows = [ps_header]
        service_recs = []
        seen_ports = set()

        for p in ports:
            port_num = str(p.get("port_number", ""))
            seen_ports.add(port_num)
            svc = svc_by_port.get(port_num, {})
            svc_name = svc.get("service_name", "") or "—"
            svc_version = svc.get("version", "") or "—"
            ps_rows.append([
                port_num,
                svc.get("protocol", p.get("protocol", "tcp")),
                p.get("state", "open"),
                svc_name,
                svc_version,
            ])
            # Collect service-specific recommendations
            rec = _get_service_recommendation(svc_name, svc_version)
            if rec and rec not in service_recs:
                service_recs.append(rec)

        # Add services that may not have a port entry
        for s in services:
            port_key = str(s.get("port", s.get("port_number", "")))
            if port_key not in seen_ports:
                svc_name = s.get("service_name", "") or "—"
                svc_version = s.get("version", "") or "—"
                ps_rows.append([
                    port_key,
                    s.get("protocol", "tcp"),
                    "open",
                    svc_name,
                    svc_version,
                ])
                rec = _get_service_recommendation(svc_name, svc_version)
                if rec and rec not in service_recs:
                    service_recs.append(rec)

        pt = Table(ps_rows, colWidths=[55, 65, 55, 120, 195])
        pt.setStyle(TableStyle(_base_table_style()))
        elements.append(pt)

        # Service-specific recommendations
        if service_recs:
            elements.append(Spacer(1, 10))
            elements.append(Paragraph(
                "<b>Service Recommendations:</b>", styles["Normal"]))
            elements.append(Spacer(1, 4))
            for i, rec in enumerate(service_recs, 1):
                elements.append(Paragraph(
                    f"<bullet>&bull;</bullet> {rec}", styles["RecBullet"]))
                elements.append(Spacer(1, 2))
    else:
        elements.append(Paragraph("No open ports or services discovered.", styles["Normal"]))
    elements.append(Spacer(1, 14))

    # ===== SECTION 4: Vulnerabilities Detected ================================
    elements.append(PageBreak())
    elements.append(Paragraph("4. Vulnerabilities Detected", styles["SectionHead"]))
    elements.append(hr)

    if vulnerabilities:
        # Summary table first
        vuln_summary_data = [
            ["Severity", "Count"],
            ["Critical", str(sev_counts["critical"])],
            ["High", str(sev_counts["high"])],
            ["Medium", str(sev_counts["medium"])],
            ["Low", str(sev_counts["low"])],
            ["Informational", str(sev_counts["info"])],
            ["Total", str(len(vulnerabilities))],
        ]
        vs = Table(vuln_summary_data, colWidths=[160, 100])
        vs_style = _base_table_style()
        sev_row_map = {1: "critical", 2: "high", 3: "medium", 4: "low", 5: "info"}
        for row_idx, sev in sev_row_map.items():
            vs_style.append(("TEXTCOLOR", (0, row_idx), (0, row_idx), _severity_color(sev)))
            vs_style.append(("FONTNAME", (0, row_idx), (0, row_idx), "Helvetica-Bold"))
        vs_style.append(("FONTNAME", (0, 6), (-1, 6), "Helvetica-Bold"))
        vs.setStyle(TableStyle(vs_style))
        elements.append(vs)
        elements.append(Spacer(1, 16))

        # Individual vulnerability entries with inline recommendations
        elements.append(Paragraph(
            "<b>Detailed Vulnerability Findings:</b>", styles["Normal"]))
        elements.append(Spacer(1, 8))

        for idx, v in enumerate(vulnerabilities, 1):
            vuln_name = v.get("vulnerability_name", "Unknown Vulnerability")
            severity = v.get("severity", "info")
            cve = v.get("cve_id", "") or "N/A"
            desc = v.get("description", "") or "No description available."
            port = v.get("port", v.get("port_number", ""))
            svc = v.get("service_name", "")

            # Build affected target string
            affected = ""
            if port:
                affected = f"Port {port}"
                if svc:
                    affected += f" ({svc})"
            elif svc:
                affected = svc

            # Vulnerability detail block
            block = []
            sev_color_hex = {
                "critical": "#dc2626", "high": "#ea580c",
                "medium": "#ca8a04", "low": "#2563eb", "info": "#6b7280",
            }.get(severity, "#6b7280")

            block.append(Paragraph(
                f"{idx}. {vuln_name}", styles["VulnTitle"]))
            block.append(Spacer(1, 3))

            details = [
                f'<b>Severity:</b> <font color="{sev_color_hex}"><b>{severity.upper()}</b></font>',
                f'<b>CVE:</b> {cve}',
            ]
            if affected:
                details.append(f'<b>Affected:</b> {affected}')
            if desc and len(desc) > 200:
                desc = desc[:197] + "..."
            details.append(f'<b>Description:</b> {desc}')

            for line in details:
                block.append(Paragraph(line, styles["VulnDetail"]))
                block.append(Spacer(1, 1))

            # Per-vulnerability recommendation
            recs = _get_vuln_recommendation(vuln_name)
            block.append(Spacer(1, 3))
            block.append(Paragraph(
                '<b><font color="#0369a1">Recommendation:</font></b>',
                styles["VulnDetail"]))
            for rec_line in recs:
                block.append(Paragraph(
                    f"<bullet>&bull;</bullet> {rec_line}", styles["RecBullet"]))

            block.append(Spacer(1, 4))
            block.append(HRFlowable(width="100%", thickness=0.5,
                                     color=colors.HexColor("#e2e8f0"),
                                     spaceAfter=6, spaceBefore=2))

            elements.append(KeepTogether(block))
    else:
        elements.append(Paragraph("No vulnerabilities found during this scan.", styles["Normal"]))
    elements.append(Spacer(1, 14))

    # ===== SECTION 5: Security Recommendations ================================
    elements.append(Paragraph("5. Security Recommendations", styles["SectionHead"]))
    elements.append(hr)

    final_recs = []

    if sev_counts["critical"] > 0:
        final_recs.append(
            f'<font color="#dc2626"><b>URGENT:</b></font> {sev_counts["critical"]} critical '
            f'vulnerabilit{"y" if sev_counts["critical"] == 1 else "ies"} detected - '
            f'immediate remediation is required.')

    final_recs.extend(build_security_recommendations(vulnerabilities, services))

    final_recs.extend([
        "Patch all outdated software and apply vendor security updates, prioritizing critical and high severity CVEs.",
        "Disable or restrict access to unnecessary open ports to reduce the attack surface.",
        "Use strong encryption algorithms for all communication channels (TLS 1.2+, AES-256).",
        "Implement web security headers: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, HSTS.",
        "Use firewall rules to restrict access to management interfaces and sensitive services.",
        "Enforce strong authentication and implement multi-factor authentication (MFA) where possible.",
        "Apply security hardening configurations following CIS Benchmarks or vendor guidelines.",
        "Implement network segmentation to limit lateral movement in case of compromise.",
        "Enable comprehensive logging and monitoring for all exposed services.",
        "Conduct periodic vulnerability scans to verify remediation effectiveness.",
    ])

    if len(ports) > 20:
        final_recs.append(
            f"Large attack surface detected ({len(ports)} open ports). "
            "Perform a thorough review and minimize exposed services.")

    deduped_recs = []
    seen_recs = set()
    for rec in final_recs:
        if rec not in seen_recs:
            deduped_recs.append(rec)
            seen_recs.add(rec)

    for i, rec in enumerate(deduped_recs, 1):
        elements.append(Paragraph(f"{i}. {rec}", styles["Normal"]))
        elements.append(Spacer(1, 4))

    elements.append(Spacer(1, 14))

    # ===== SECTION 6: Risk Assessment =========================================
    elements.append(Paragraph("6. Risk Assessment", styles["SectionHead"]))
    elements.append(hr)

    risk_data = [
        ["Metric", "Value"],
        ["Overall Risk Score", f"{risk_score} / 100"],
        ["Risk Level", risk_label],
        ["Critical Vulnerabilities", str(sev_counts["critical"])],
        ["High Vulnerabilities", str(sev_counts["high"])],
        ["Medium Vulnerabilities", str(sev_counts["medium"])],
        ["Low Vulnerabilities", str(sev_counts["low"])],
        ["Open Ports", str(len(ports))],
        ["Detected Services", str(len(services))],
    ]
    rt = Table(risk_data, colWidths=[200, 100])
    rt_style = _base_table_style()
    risk_sev_rows = {3: "critical", 4: "high", 5: "medium", 6: "low"}
    for row_idx, sev in risk_sev_rows.items():
        rt_style.append(("TEXTCOLOR", (0, row_idx), (0, row_idx), _severity_color(sev)))
        rt_style.append(("FONTNAME", (0, row_idx), (0, row_idx), "Helvetica-Bold"))
    # Color the risk level row
    risk_sev_key = risk_label.lower()
    if risk_sev_key in _SEV_COLORS:
        rt_style.append(("TEXTCOLOR", (1, 2), (1, 2), _severity_color(risk_sev_key)))
        rt_style.append(("FONTNAME", (1, 2), (1, 2), "Helvetica-Bold"))
    rt.setStyle(TableStyle(rt_style))
    elements.append(rt)
    elements.append(Spacer(1, 14))

    # ===== SECTION 7: Conclusion ==============================================
    elements.append(Paragraph("7. Conclusion", styles["SectionHead"]))
    elements.append(hr)

    conclusion_lines = [
        f'This scan of <b>{asset.get("asset_name", "N/A")}</b> ({scan_type} scan) '
        f'identified <b>{len(vulnerabilities)}</b> vulnerabilities across '
        f'<b>{len(ports)}</b> open ports and <b>{len(services)}</b> services.',
    ]

    if sev_counts["critical"] > 0 or sev_counts["high"] > 0:
        conclusion_lines.append(
            f'<font color="#dc2626"><b>{sev_counts["critical"]} critical</b></font> and '
            f'<font color="#ea580c"><b>{sev_counts["high"]} high</b></font> severity '
            f'vulnerabilities require immediate attention.')

    if risk_score >= 51:
        conclusion_lines.append(
            f'The overall risk level is <b>{risk_label}</b> (score: {risk_score}/100). '
            f'Prompt remediation is strongly recommended to reduce exposure.')
    else:
        conclusion_lines.append(
            f'The overall risk level is <b>{risk_label}</b> (score: {risk_score}/100). '
            f'Continue regular scanning and maintain security hygiene.')

    conclusion_lines.append(
        'All identified vulnerabilities should be addressed according to their severity, '
        'with critical and high findings prioritized for immediate remediation.')

    for line in conclusion_lines:
        elements.append(Paragraph(line, styles["Normal"]))
        elements.append(Spacer(1, 6))

    elements.append(Spacer(1, 24))
    elements.append(hr)
    elements.append(Paragraph(
        f'<i>This report was automatically generated by the VAPT Dashboard on '
        f'{datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC.</i>',
        styles["Meta"],
    ))

    # Build PDF
    doc.build(elements)
    return buf.getvalue()
