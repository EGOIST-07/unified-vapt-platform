"""Parse raw scanner outputs and extract structured vulnerability/service data."""

import json
import logging
import re
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)


# ─── Nmap XML Parser ──────────────────────────────────────────────────────────

def parse_nmap(raw_xml: str) -> dict:
    """Parse Nmap XML output into structured data.
    
    Returns:
        {
            "hosts": [{
                "ip": str, "hostname": str, "os": str, "status": str,
                "ports": [{"port": int, "protocol": str, "state": str,
                           "service": str, "version": str}],
                "vulnerabilities": [{"title": str, "severity": str, ...}]
            }]
        }
    """
    result = {"hosts": []}
    if not raw_xml or not raw_xml.strip():
        return result

    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError as e:
        logger.error("Failed to parse Nmap XML: %s", e)
        return result

    for host_elem in root.findall(".//host"):
        status = host_elem.find("status")
        if status is not None and status.get("state") != "up":
            continue

        host = {
            "ip": "",
            "hostname": "",
            "os": "",
            "status": "up",
            "ports": [],
            "vulnerabilities": [],
        }

        # IP address
        addr = host_elem.find("address[@addrtype='ipv4']")
        if addr is None:
            addr = host_elem.find("address[@addrtype='ipv6']")
        if addr is not None:
            host["ip"] = addr.get("addr", "")

        # Hostname
        hostname_elem = host_elem.find(".//hostname")
        if hostname_elem is not None:
            host["hostname"] = hostname_elem.get("name", "")

        # OS detection
        osmatch = host_elem.find(".//osmatch")
        if osmatch is not None:
            host["os"] = osmatch.get("name", "")

        # Ports and services
        for port_elem in host_elem.findall(".//port"):
            state_elem = port_elem.find("state")
            service_elem = port_elem.find("service")

            port_info = {
                "port": int(port_elem.get("portid", 0)),
                "protocol": port_elem.get("protocol", "tcp"),
                "state": state_elem.get("state", "unknown") if state_elem is not None else "unknown",
                "service": service_elem.get("name", "") if service_elem is not None else "",
                "version": "",
            }
            if service_elem is not None:
                version_parts = [
                    service_elem.get("product", ""),
                    service_elem.get("version", ""),
                    service_elem.get("extrainfo", ""),
                ]
                port_info["version"] = " ".join(p for p in version_parts if p).strip()

            host["ports"].append(port_info)

            # NSE script output → vulnerabilities
            for script in port_elem.findall(".//script"):
                vuln = _parse_nmap_script(script, port_info)
                if vuln:
                    host["vulnerabilities"].append(vuln)

        # Host-level scripts
        for script in host_elem.findall(".//hostscript/script"):
            vuln = _parse_nmap_script(script, None)
            if vuln:
                host["vulnerabilities"].append(vuln)

        result["hosts"].append(host)

    return result


def _parse_nmap_script(script_elem, port_info: dict | None) -> dict | None:
    script_id = script_elem.get("id", "")
    output = script_elem.get("output", "")

    if not output or "ERROR" in output or "false" == output.strip().lower():
        return None

    # Detect CVEs in script output
    cve_match = re.search(r"(CVE-\d{4}-\d+)", output)
    cve_id = cve_match.group(1) if cve_match else None

    # Determine severity from script type
    severity = "info"
    vuln_scripts = {"vulners", "vulscan", "smb-vuln", "ssl-heartbleed",
                    "ssl-poodle", "http-shellshock", "ms-sql-info"}
    for vs in vuln_scripts:
        if vs in script_id:
            severity = "high"
            break

    if "vuln" in script_id.lower() and "VULNERABLE" in output:
        severity = "critical"

    port_str = f" (port {port_info['port']})" if port_info else ""

    return {
        "title": f"{script_id}{port_str}",
        "description": output[:2000],
        "severity": severity,
        "cve_id": cve_id,
        "scanner": "nmap",
        "evidence": output[:5000],
    }


# ─── Masscan JSON Parser ──────────────────────────────────────────────────────

def parse_masscan(raw_json: str) -> dict:
    """Parse Masscan JSON output.
    
    Returns: {"hosts": [{"ip": str, "ports": [{"port": int, "protocol": str, "state": str}]}]}
    """
    result = {"hosts": []}
    if not raw_json or not raw_json.strip():
        return result

    # Masscan JSON can have trailing commas, fix it
    cleaned = raw_json.strip()
    if cleaned.endswith(",]"):
        cleaned = cleaned[:-2] + "]"
    if cleaned.endswith(",\n]"):
        cleaned = cleaned.replace(",\n]", "\n]")

    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        # Try line-by-line parsing
        data = []
        for line in raw_json.splitlines():
            line = line.strip().rstrip(",")
            if line.startswith("{"):
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    hosts = {}
    for entry in data:
        ip = entry.get("ip", "")
        if not ip:
            continue
        if ip not in hosts:
            hosts[ip] = {"ip": ip, "ports": []}

        for port_info in entry.get("ports", []):
            hosts[ip]["ports"].append({
                "port": port_info.get("port", 0),
                "protocol": port_info.get("proto", "tcp"),
                "state": "open",
            })

    result["hosts"] = list(hosts.values())
    return result


# ─── Nuclei JSONL Parser ──────────────────────────────────────────────────────

def parse_nuclei(raw_jsonl: str) -> list[dict]:
    """Parse Nuclei JSONL output into vulnerability list."""
    vulnerabilities = []
    if not raw_jsonl or not raw_jsonl.strip():
        return vulnerabilities

    severity_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
        "unknown": "info",
    }

    for line in raw_jsonl.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            finding = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = finding.get("info", {})
        severity = severity_map.get(
            info.get("severity", "info").lower(), "info"
        )

        # Extract CVE/CWE if present
        classification = info.get("classification", {})
        cve_ids = classification.get("cve-id", [])
        cwe_ids = classification.get("cwe-id", [])
        cvss = info.get("classification", {}).get("cvss-score")

        refs = info.get("reference", [])
        if isinstance(refs, str):
            refs = [refs]

        vuln = {
            "title": info.get("name", finding.get("template-id", "Unknown")),
            "description": info.get("description", ""),
            "severity": severity,
            "cvss_score": float(cvss) if cvss else None,
            "cve_id": cve_ids[0] if cve_ids else None,
            "cwe_id": cwe_ids[0] if cwe_ids else None,
            "scanner": "nuclei",
            "evidence": json.dumps({
                "matched_at": finding.get("matched-at", ""),
                "matcher_name": finding.get("matcher-name", ""),
                "extracted_results": finding.get("extracted-results", []),
                "curl_command": finding.get("curl-command", ""),
            }),
            "remediation": info.get("remediation", ""),
            "reference_urls": refs,
        }
        vulnerabilities.append(vuln)

    return vulnerabilities


# ─── OpenVAS XML Parser ───────────────────────────────────────────────────────

def parse_openvas(raw_xml: str) -> list[dict]:
    """Parse OpenVAS/GVM XML results."""
    vulnerabilities = []
    if not raw_xml or not raw_xml.strip():
        return vulnerabilities

    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError as e:
        logger.error("Failed to parse OpenVAS XML: %s", e)
        return vulnerabilities

    threat_map = {
        "High": "high",
        "Medium": "medium",
        "Low": "low",
        "Log": "info",
        "Alarm": "critical",
    }

    for result in root.findall(".//result"):
        name = result.findtext("name", "")
        threat = result.findtext("threat", "info")
        description = result.findtext("description", "")
        host_elem = result.find("host")
        port_text = result.findtext("port", "")

        severity = threat_map.get(threat, "info")

        # Extract CVE
        nvt = result.find("nvt")
        cve_id = None
        refs = []
        if nvt is not None:
            cve_text = nvt.findtext("cve", "")
            if cve_text and cve_text != "NOCVE":
                cve_match = re.search(r"(CVE-\d{4}-\d+)", cve_text)
                cve_id = cve_match.group(1) if cve_match else None

            xref = nvt.findtext("xref", "")
            if xref:
                refs = [x.strip() for x in xref.split(",") if x.strip()]

        cvss = nvt.findtext("cvss_base") if nvt is not None else None

        vuln = {
            "title": name,
            "description": description[:2000],
            "severity": severity,
            "cvss_score": float(cvss) if cvss else None,
            "cve_id": cve_id,
            "scanner": "openvas",
            "evidence": f"Host: {host_elem.text if host_elem is not None else 'N/A'}, Port: {port_text}",
            "reference_urls": refs,
        }
        vulnerabilities.append(vuln)

    return vulnerabilities


# ─── ZAP JSON Parser ──────────────────────────────────────────────────────────

def parse_zap(raw_json: str) -> list[dict]:
    """Parse OWASP ZAP JSON report."""
    vulnerabilities = []
    if not raw_json or not raw_json.strip():
        return vulnerabilities

    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as e:
        logger.error("Failed to parse ZAP JSON: %s", e)
        return vulnerabilities

    risk_map = {0: "info", 1: "low", 2: "medium", 3: "high"}

    # ZAP report formats can vary
    sites = data.get("site", [])
    if isinstance(sites, dict):
        sites = [sites]

    for site in sites:
        for alert in site.get("alerts", []):
            risk_code = int(alert.get("riskcode", 0))
            severity = risk_map.get(risk_code, "info")

            # Collect evidence from instances
            instances = alert.get("instances", [])
            evidence_parts = []
            for inst in instances[:5]:
                uri = inst.get("uri", "")
                method = inst.get("method", "")
                evidence_parts.append(f"{method} {uri}")

            cwe_id = alert.get("cweid", "")
            cwe_str = f"CWE-{cwe_id}" if cwe_id and cwe_id != "-1" else None

            vuln = {
                "title": alert.get("name", alert.get("alert", "Unknown")),
                "description": alert.get("desc", "")[:2000],
                "severity": severity,
                "cwe_id": cwe_str,
                "scanner": "zap",
                "evidence": "\n".join(evidence_parts),
                "remediation": alert.get("solution", ""),
                "reference_urls": [r for r in alert.get("reference", "").split("\n") if r.strip()],
            }
            vulnerabilities.append(vuln)

    return vulnerabilities


# ─── Nikto JSON Parser ────────────────────────────────────────────────────────

def parse_nikto(raw_json: str) -> list[dict]:
    """Parse Nikto JSON output."""
    vulnerabilities = []
    if not raw_json or not raw_json.strip():
        return vulnerabilities

    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as e:
        logger.warning("Failed to parse Nikto JSON: %s", e)
        return vulnerabilities

    # Nikto JSON format
    if isinstance(data, dict):
        data = [data]

    for host_data in data:
        for vuln_item in host_data.get("vulnerabilities", []):
            osvdb_id = vuln_item.get("OSVDB", "")
            method = vuln_item.get("method", "GET")
            url = vuln_item.get("url", "")
            msg = vuln_item.get("msg", "")

            # Nikto doesn't provide severity, estimate from OSVDB/content
            severity = "low"
            high_indicators = ["remote code", "injection", "traversal",
                               "arbitrary", "command execution", "backdoor"]
            medium_indicators = ["disclosure", "default", "misconfiguration",
                                 "outdated", "deprecated"]
            for indicator in high_indicators:
                if indicator in msg.lower():
                    severity = "high"
                    break
            if severity == "low":
                for indicator in medium_indicators:
                    if indicator in msg.lower():
                        severity = "medium"
                        break

            vuln = {
                "title": msg[:200] if msg else f"Nikto finding (OSVDB-{osvdb_id})",
                "description": msg,
                "severity": severity,
                "scanner": "nikto",
                "evidence": f"{method} {url}",
                "reference_urls": [f"https://osvdb.org/{osvdb_id}"] if osvdb_id and osvdb_id != "0" else [],
            }
            vulnerabilities.append(vuln)

    return vulnerabilities


# ─── Unified Parser ───────────────────────────────────────────────────────────

PARSER_MAP = {
    "nmap": lambda raw: parse_nmap(raw),
    "masscan": lambda raw: parse_masscan(raw),
    "nuclei": lambda raw: parse_nuclei(raw),
    "openvas": lambda raw: parse_openvas(raw),
    "zap": lambda raw: parse_zap(raw),
    "nikto": lambda raw: parse_nikto(raw),
}


def parse_scan_output(scanner: str, raw_output: str) -> dict:
    """Unified entry point: parse output from any supported scanner.
    
    Returns a dict with normalized keys:
        - "services": list of {port, protocol, state, service, version}
        - "vulnerabilities": list of {title, description, severity, ...}
        - "hosts": list of host dicts (for nmap/masscan)
    """
    parser = PARSER_MAP.get(scanner)
    if not parser:
        return {"services": [], "vulnerabilities": [], "hosts": []}

    parsed = parser(raw_output)

    # Normalize based on scanner type
    if scanner in ("nmap", "masscan"):
        # These return {"hosts": [...]}
        services = []
        vulns = []
        for host in parsed.get("hosts", []):
            for p in host.get("ports", []):
                services.append(p)
            for v in host.get("vulnerabilities", []):
                vulns.append(v)
        return {
            "hosts": parsed.get("hosts", []),
            "services": services,
            "vulnerabilities": vulns,
        }
    else:
        # Nuclei, OpenVAS, ZAP, Nikto return vulnerability lists
        return {
            "hosts": [],
            "services": [],
            "vulnerabilities": parsed if isinstance(parsed, list) else [],
        }


def calculate_risk_score(vulnerabilities: list[dict]) -> float:
    """Calculate risk score from a list of vulnerabilities."""
    weights = {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 1.0}
    weighted_total = sum(weights.get(v.get("severity", "info"), 0.0) for v in vulnerabilities)
    weighted_count = sum(1 for v in vulnerabilities if v.get("severity") in weights)
    if weighted_count <= 0:
        return 0.0
    max_possible = weighted_count * 10.0
    return min((weighted_total / max_possible) * 100.0, 100.0)
