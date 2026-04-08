"""Security scanner integrations — Nmap, Masscan, Nuclei, OpenVAS, ZAP, Nikto.

All scanners run via subprocess and return raw output for the parser module.
"""

import asyncio
import json
import logging
import os
import re
import shutil
import socket
import tempfile
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

SCAN_OUTPUT_DIR = os.getenv("SCAN_OUTPUT_DIR", "/tmp/vapt_scans")
os.makedirs(SCAN_OUTPUT_DIR, exist_ok=True)


@dataclass
class ScanResult:
    scanner: str
    target: str
    success: bool
    raw_output: str = ""
    output_file: str = ""
    error: str = ""
    return_code: int = 0


async def _run_cmd(cmd: list[str], timeout: int = 600) -> tuple[int, str, str]:
    """Execute a command async and return (returncode, stdout, stderr)."""
    logger.info("Running: %s", " ".join(cmd))
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return -1, "", "Scan timed out"
    return proc.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")


def _check_tool(tool_name: str) -> bool:
    return shutil.which(tool_name) is not None


def _has_http_service(nmap_xml: str) -> bool:
    """Check nmap XML output for open HTTP/HTTPS ports (80, 443, 8080, 8443, or http* service)."""
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(nmap_xml)
        for port_elem in root.iter("port"):
            state = port_elem.find("state")
            if state is not None and state.get("state") != "open":
                continue
            port_id = port_elem.get("portid", "")
            if port_id in ("80", "443", "8080", "8443"):
                return True
            svc = port_elem.find("service")
            if svc is not None and (svc.get("name", "").startswith("http") or
                                     svc.get("name", "") in ("https", "ssl/http")):
                return True
    except ET.ParseError:
        pass
    return False


def _extract_open_ports(nmap_xml: str) -> set[int]:
    """Extract open TCP/UDP ports from nmap XML output."""
    open_ports: set[int] = set()
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(nmap_xml)
        for port_elem in root.iter("port"):
            state = port_elem.find("state")
            if state is None or state.get("state") != "open":
                continue
            port_id = port_elem.get("portid", "")
            if port_id.isdigit():
                open_ports.add(int(port_id))
    except Exception:
        return set()
    return open_ports


def _looks_like_ip_or_cidr(target: str) -> bool:
    if "/" in target:
        try:
            import ipaddress
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            return False
    try:
        socket.inet_aton(target)
        return True
    except OSError:
        return False


def _resolve_target(target: str) -> tuple[bool, str]:
    """Resolve target when hostname/domain; for IP/CIDR skip DNS resolution."""
    if _looks_like_ip_or_cidr(target):
        return True, ""

    # Retry name resolution to absorb transient DNS hiccups from container networking.
    attempts = int(os.getenv("DNS_RESOLVE_RETRIES", "4"))
    delay_s = float(os.getenv("DNS_RESOLVE_RETRY_DELAY_S", "1.2"))
    last_exc: Optional[Exception] = None

    for attempt in range(1, attempts + 1):
        try:
            socket.getaddrinfo(target, None)
            return True, ""
        except socket.gaierror as exc:
            last_exc = exc
            logger.warning(
                "DNS resolution attempt %s/%s failed for %s: %s",
                attempt,
                attempts,
                target,
                exc,
            )
            if attempt < attempts:
                time.sleep(delay_s)

    return False, f"DNS resolution failed for {target}: {last_exc}"


async def _http_available(url: str, timeout: int = 8) -> bool:
    """Check whether target URL is reachable and returns an HTTP response."""
    if not _check_tool("curl"):
        # If curl is unavailable, do not hard fail due to environment limitations.
        return True
    rc, stdout, stderr = await _run_cmd(
        ["curl", "-kIsS", "--max-time", str(timeout), url], timeout=timeout + 2,
    )
    if rc != 0:
        return False
    return bool(re.search(r"^HTTP/", stdout, re.MULTILINE))


def _build_web_targets(target: str, open_ports: set[int]) -> list[tuple[str, int]]:
    """Build protocol fallback targets for detected web ports."""
    candidates: list[tuple[str, int]] = []
    seen: set[str] = set()

    for port in sorted(open_ports):
        if port not in {80, 443, 8080, 8443}:
            continue

        # Keep protocol/port pairings sane to avoid expensive dead-end probes.
        # 80/8080 -> http, 443/8443 -> https.
        scheme = "https" if port in {443, 8443} else "http"
        is_default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
        suffix = "" if is_default else f":{port}"
        url = f"{scheme}://{target}{suffix}"
        if url not in seen:
            seen.add(url)
            candidates.append((url, port))

    return candidates


# ─── Nmap ──────────────────────────────────────────────────────────────────────

async def run_nmap(target: str, ports: str = None, scan_type: str = "default",
                   scripts: list[str] = None, timeout: int = 900) -> ScanResult:
    """Run an Nmap scan on the target.
    
    scan_type: 'default', 'quick', 'full', 'vuln', 'stealth'
    """
    if not _check_tool("nmap"):
        return ScanResult("nmap", target, False, error="nmap not installed")

    uid = int(time.time() * 1000) % 1_000_000
    outfile = os.path.join(SCAN_OUTPUT_DIR, f"nmap_{scan_type}_{target.replace('/', '_')}_{uid}.xml")
    cmd = ["nmap", "-oX", outfile]

    if scan_type == "quick":
        cmd += ["-T4", "-F", "-sV"]
    elif scan_type == "discovery":
        cmd += ["-sn", "-T4"]
    elif scan_type == "full":
        cmd += ["-sV", "-sC", "-T4", "--top-ports", "1000"]
    elif scan_type == "vuln":
        cmd += ["-sV", "--script", "vuln", "-T4", "--script-timeout", "30s"]
    elif scan_type == "stealth":
        cmd += ["-sS", "-T2", "-f"]
    else:
        cmd += ["-sV", "-sC", "-T4"]

    if ports:
        cmd += ["-p", ports]
    if scripts:
        cmd += ["--script", ",".join(scripts)]

    cmd.append(target)

    rc, stdout, stderr = await _run_cmd(cmd, timeout)
    raw = ""
    if os.path.exists(outfile):
        with open(outfile) as f:
            raw = f.read()

    return ScanResult(
        scanner="nmap", target=target, success=(rc == 0),
        raw_output=raw or stdout, output_file=outfile,
        error=stderr if rc != 0 else "", return_code=rc,
    )


# ─── Masscan ──────────────────────────────────────────────────────────────────

async def run_masscan(target: str, ports: str = "1-65535",
                      rate: int = 10000, timeout: int = 600) -> ScanResult:
    """Run Masscan for fast port discovery on IP/CIDR targets."""
    if not _check_tool("masscan"):
        return ScanResult("masscan", target, False, error="masscan not installed")

    outfile = os.path.join(SCAN_OUTPUT_DIR, f"masscan_{target.replace('/', '_')}_{os.getpid()}.json")
    cmd = [
        "masscan", target,
        "-p", ports,
        "--rate", str(rate),
        "--open",
        "-oJ", outfile,
    ]

    rc, stdout, stderr = await _run_cmd(cmd, timeout)
    raw = ""
    if os.path.exists(outfile):
        with open(outfile) as f:
            raw = f.read()

    return ScanResult(
        scanner="masscan", target=target, success=(rc == 0),
        raw_output=raw or stdout, output_file=outfile,
        error=stderr if rc != 0 else "", return_code=rc,
    )


# ─── Nuclei ───────────────────────────────────────────────────────────────────

async def run_nuclei(target: str, templates: list[str] = None,
                     severity: str = None, timeout: int = 900) -> ScanResult:
    """Run Nuclei template-based vulnerability scanner."""
    if not _check_tool("nuclei"):
        return ScanResult("nuclei", target, False, error="nuclei not installed")

    safe_name = re.sub(r'[/:]+', '_', target)
    outfile = os.path.join(SCAN_OUTPUT_DIR, f"nuclei_{safe_name}_{os.getpid()}.json")
    cmd = ["nuclei", "-u", target, "-jsonl", "-o", outfile, "-silent"]

    if templates:
        for t in templates:
            cmd += ["-t", t]
    if severity:
        cmd += ["-severity", severity]

    rc, stdout, stderr = await _run_cmd(cmd, timeout)
    raw = ""
    if os.path.exists(outfile):
        with open(outfile) as f:
            raw = f.read()

    return ScanResult(
        scanner="nuclei", target=target, success=(rc == 0),
        raw_output=raw or stdout, output_file=outfile,
        error=stderr if rc != 0 else "", return_code=rc,
    )


# ─── OpenVAS ──────────────────────────────────────────────────────────────────

async def run_openvas(target: str, scan_config: str = "full_and_fast",
                      timeout: int = 3600) -> ScanResult:
    """Run OpenVAS vulnerability scan via gvm-cli."""
    if not _check_tool("gvm-cli"):
        return ScanResult("openvas", target, False, error="gvm-cli not installed")

    gvm_socket = os.getenv("GVM_SOCKET", "/var/run/gvmd/gvmd.sock")
    gvm_user = os.getenv("GVM_USER", "admin")
    gvm_pass = os.getenv("GVM_PASSWORD", "admin")

    # Create target in OpenVAS
    create_target_xml = f'<create_target><name>vapt_{target}</name><hosts>{target}</hosts></create_target>'
    rc, stdout, stderr = await _run_cmd([
        "gvm-cli", "--gmp-username", gvm_user, "--gmp-password", gvm_pass,
        "socket", "--socketpath", gvm_socket, "--xml", create_target_xml,
    ], timeout=60)

    if rc != 0:
        return ScanResult("openvas", target, False, error=f"Failed to create target: {stderr}")

    # Extract target ID from response
    import re
    match = re.search(r'id="([a-f0-9-]+)"', stdout)
    if not match:
        return ScanResult("openvas", target, False, error="Failed to get target ID")
    target_id = match.group(1)

    # Get scan config ID
    config_map = {
        "full_and_fast": "daba56c8-73ec-11df-a475-002264764cea",
        "full_and_deep": "708f25c4-7489-11df-8094-002264764cea",
        "discovery": "8715c877-47a0-438d-98a3-27c7a6ab2196",
    }
    config_id = config_map.get(scan_config, config_map["full_and_fast"])

    # Create and start task
    scanner_id = "08b69003-5fc2-4037-a479-93b440211c73"
    create_task_xml = (
        f'<create_task><name>vapt_scan_{target}</name>'
        f'<target id="{target_id}"/>'
        f'<config id="{config_id}"/>'
        f'<scanner id="{scanner_id}"/></create_task>'
    )
    rc, stdout, stderr = await _run_cmd([
        "gvm-cli", "--gmp-username", gvm_user, "--gmp-password", gvm_pass,
        "socket", "--socketpath", gvm_socket, "--xml", create_task_xml,
    ], timeout=60)

    match = re.search(r'id="([a-f0-9-]+)"', stdout)
    if not match:
        return ScanResult("openvas", target, False, error="Failed to create task")
    task_id = match.group(1)

    # Start the task
    start_xml = f'<start_task task_id="{task_id}"/>'
    rc, stdout, stderr = await _run_cmd([
        "gvm-cli", "--gmp-username", gvm_user, "--gmp-password", gvm_pass,
        "socket", "--socketpath", gvm_socket, "--xml", start_xml,
    ], timeout=60)

    # Poll for completion
    import time
    elapsed = 0
    while elapsed < timeout:
        await asyncio.sleep(15)
        elapsed += 15
        get_task_xml = f'<get_tasks task_id="{task_id}"/>'
        rc, stdout, _ = await _run_cmd([
            "gvm-cli", "--gmp-username", gvm_user, "--gmp-password", gvm_pass,
            "socket", "--socketpath", gvm_socket, "--xml", get_task_xml,
        ], timeout=30)
        if "Done" in stdout:
            break

    # Get results
    get_results_xml = f'<get_results task_id="{task_id}"/>'
    rc, stdout, stderr = await _run_cmd([
        "gvm-cli", "--gmp-username", gvm_user, "--gmp-password", gvm_pass,
        "socket", "--socketpath", gvm_socket, "--xml", get_results_xml,
    ], timeout=120)

    return ScanResult(
        scanner="openvas", target=target, success=(rc == 0),
        raw_output=stdout, error=stderr if rc != 0 else "",
        return_code=rc,
    )


# ─── OWASP ZAP ────────────────────────────────────────────────────────────────

async def run_zap(target: str, scan_type: str = "baseline",
                  timeout: int = 1800) -> ScanResult:
    """Run OWASP ZAP scan (baseline, full, or api)."""
    has_zap_cli = _check_tool("zap-cli")
    has_zap_sh = _check_tool("zap.sh")
    if not has_zap_cli and not has_zap_sh:
        return ScanResult("zap", target, False, error="zap-cli / zap.sh not installed")

    outfile = os.path.join(SCAN_OUTPUT_DIR, f"zap_{target.replace('/', '_')}_{os.getpid()}.json")

    # Only use Docker if native ZAP tools are not available
    if not has_zap_cli and not has_zap_sh and _check_tool("docker"):
        scan_script = {
            "baseline": "zap-baseline.py",
            "full": "zap-full-scan.py",
            "api": "zap-api-scan.py",
        }.get(scan_type, "zap-baseline.py")

        cmd = [
            "docker", "run", "--rm", "-v", f"{SCAN_OUTPUT_DIR}:/zap/wrk",
            "ghcr.io/zaproxy/zaproxy:stable",
            scan_script, "-t", target, "-J", os.path.basename(outfile),
        ]
    else:
        zap_api_key = os.getenv("ZAP_API_KEY", "")
        cmd = ["zap-cli", "--api-key", zap_api_key]
        if scan_type == "full":
            cmd += ["active-scan", target]
        else:
            cmd += ["quick-scan", target]

    rc, stdout, stderr = await _run_cmd(cmd, timeout)
    raw = ""
    if os.path.exists(outfile):
        with open(outfile) as f:
            raw = f.read()

    return ScanResult(
        scanner="zap", target=target, success=(rc in (0, 1, 2)),
        raw_output=raw or stdout, output_file=outfile,
        error=stderr if rc not in (0, 1, 2) else "", return_code=rc,
    )


# ─── Nikto ─────────────────────────────────────────────────────────────────────

async def run_nikto(target: str, port: int = None,
                    timeout: int = 600) -> ScanResult:
    """Run Nikto web server scanner."""
    if not _check_tool("nikto"):
        return ScanResult("nikto", target, False, error="nikto not installed")

    outfile = os.path.join(SCAN_OUTPUT_DIR, f"nikto_{target.replace('/', '_')}_{os.getpid()}.json")
    cmd = ["nikto", "-h", target, "-Format", "json", "-output", outfile, "-nointeractive"]
    if port:
        cmd += ["-p", str(port)]

    rc, stdout, stderr = await _run_cmd(cmd, timeout)
    raw = ""
    if os.path.exists(outfile):
        with open(outfile) as f:
            raw = f.read()

    return ScanResult(
        scanner="nikto", target=target, success=(rc == 0),
        raw_output=raw or stdout, output_file=outfile,
        error=stderr if rc != 0 else "", return_code=rc,
    )


# ─── Orchestrator ──────────────────────────────────────────────────────────────

SCANNER_MAP = {
    "nmap": run_nmap,
    "masscan": run_masscan,
    "nuclei": run_nuclei,
    "openvas": run_openvas,
    "zap": run_zap,
    "nikto": run_nikto,
}


async def run_scan(scanner: str, target: str, **kwargs) -> ScanResult:
    """Run a specific scanner by name."""
    func = SCANNER_MAP.get(scanner)
    if not func:
        return ScanResult(scanner, target, False, error=f"Unknown scanner: {scanner}")
    return await func(target, **kwargs)


async def run_quick_scan(target: str, asset_type: str) -> list[ScanResult]:
    """Quick Scan: fast port scan with service detection + nuclei if HTTP/HTTPS open.

    Pipeline: nmap -T4 -F -sV → (if HTTP/HTTPS open) nuclei medium,high,critical
    Estimated time: 30s – 3min
    """
    results = []

    # Validation checks before scan to avoid silent empty outputs.
    ok, reason = _resolve_target(target)
    if not ok:
        raise RuntimeError(reason)

    # Fast Nmap port scan with service version detection (-T4 -F -sV)
    nmap_result = await run_nmap(target, scan_type="quick", timeout=120)
    results.append(nmap_result)

    if not nmap_result.success:
        raise RuntimeError(nmap_result.error or "Quick scan nmap phase failed")

    open_ports = _extract_open_ports(nmap_result.raw_output)
    if not open_ports:
        raise RuntimeError(
            f"Target {target} did not expose reachable open ports during quick scan"
        )

    web_ports = sorted(p for p in open_ports if p in {80, 443, 8080})

    # Automatic web target detection for lightweight vulnerability checks.
    if web_ports:
        web_targets = _build_web_targets(target, set(web_ports))

        reachable_targets: list[tuple[str, int]] = []
        for web_target, web_port in web_targets:
            if await _http_available(web_target):
                reachable_targets.append((web_target, web_port))

        if not reachable_targets:
            raise RuntimeError(
                f"Web ports were detected for {target}, but no HTTP response was reachable"
            )

        # Keep quick scans responsive for demo/runtime stability.
        quick_targets = reachable_targets[:1]

        if _check_tool("nuclei"):
            for web_target, _ in quick_targets:
                nuclei_result = await run_nuclei(
                    web_target, severity="critical,high,medium,low", timeout=90,
                )
                results.append(nuclei_result)

                if web_target.startswith("https://"):
                    ssl_nuclei_result = await run_nuclei(
                        web_target,
                        templates=["/root/nuclei-templates/ssl/expired-ssl.yaml",
                                   "/root/nuclei-templates/ssl/self-signed-ssl.yaml",
                                   "/root/nuclei-templates/ssl/deprecated-tls.yaml",
                                   "/root/nuclei-templates/ssl/tls-version.yaml",
                                   "/root/nuclei-templates/ssl/weak-cipher-suites.yaml"],
                        severity="critical,high,medium,low",
                        timeout=90,
                    )
                    results.append(ssl_nuclei_result)

        # Requirement: if 80/443/8080 are open, trigger Nikto as well.
        if _check_tool("nikto"):
            for web_target, web_port in quick_targets:
                nikto_result = await run_nikto(web_target, port=web_port, timeout=90)
                results.append(nikto_result)

    return results


async def run_network_scan(target: str, asset_type: str) -> list[ScanResult]:
    """Network Scan: masscan port discovery + nmap service detection.

    Estimated time: 1 – 5min
    """
    results = []

    # Phase 1: host discovery (non-vulnerability)
    discovery_result = await run_nmap(target, scan_type="discovery", timeout=120)
    results.append(discovery_result)

    # Phase 2: high-speed port discovery for infra targets
    if asset_type in ("ip", "cidr") and _check_tool("masscan"):
        # Masscan fast port discovery
        masscan_result = await run_masscan(
            target, ports="1-65535", rate=1000, timeout=300,
        )
        results.append(masscan_result)

    # Phase 3: service detection only (no vulnerability scanners)
    nmap_result = await run_nmap(target, scan_type="quick", timeout=300)
    results.append(nmap_result)

    return results


async def run_full_scan(target: str, asset_type: str) -> list[ScanResult]:
    """Full Scan: deep vulnerability assessment with all available tools.

    Pipeline: ports → services → vuln scripts → nuclei → nikto → subfinder
    Estimated time: 5 – 20min
    """
    results = []

    # Phase 1: Nmap full service detection
    nmap_result = await run_nmap(target, scan_type="full", timeout=300)
    results.append(nmap_result)

    # Phase 2: Nmap vulnerability scripts (--script-timeout 30s caps individual scripts)
    nmap_vuln = await run_nmap(target, scan_type="vuln", timeout=180)
    results.append(nmap_vuln)

    open_ports = _extract_open_ports(nmap_result.raw_output)
    has_http = bool({80, 443, 8080, 8443} & open_ports) or _has_http_service(nmap_result.raw_output)

    # Phase 3: Nuclei (all severities), prefer URL targets for web services.
    if _check_tool("nuclei"):
        nuclei_targets: list[str] = []
        if has_http:
            nuclei_targets = [url for url, _ in _build_web_targets(target, open_ports)]
        if not nuclei_targets:
            nuclei_targets = [target]
        for n_target in nuclei_targets[:2]:
            nuclei_result = await run_nuclei(n_target, timeout=240)
            results.append(nuclei_result)

            if n_target.startswith("https://"):
                ssl_nuclei_result = await run_nuclei(
                    n_target,
                    templates=["/root/nuclei-templates/ssl/expired-ssl.yaml",
                               "/root/nuclei-templates/ssl/self-signed-ssl.yaml",
                               "/root/nuclei-templates/ssl/deprecated-tls.yaml",
                               "/root/nuclei-templates/ssl/tls-version.yaml",
                               "/root/nuclei-templates/ssl/weak-cipher-suites.yaml"],
                    severity="critical,high,medium,low",
                    timeout=240,
                )
                results.append(ssl_nuclei_result)

    # Phase 4: Nikto web scanning when web ports/services detected.
    if has_http and _check_tool("nikto"):
        nikto_targets: list[tuple[str, int | None]] = []
        nikto_targets = [(url, port) for url, port in _build_web_targets(target, open_ports)]

        if not nikto_targets and asset_type in ("domain", "subdomain"):
            nikto_targets = [(target, None)]

        for n_target, n_port in nikto_targets[:2]:
            nikto_result = await run_nikto(n_target, port=n_port, timeout=180)
            results.append(nikto_result)

    # Phase 5: Subfinder subdomain discovery (domains only)
    if asset_type == "domain" and _check_tool("subfinder"):
        subfinder_result = await _run_subfinder(target, timeout=120)
        results.append(subfinder_result)

    # Phase 6: Masscan for CIDR ranges
    if asset_type == "cidr" and _check_tool("masscan"):
        masscan_result = await run_masscan(target, ports="1-10000", rate=5000, timeout=300)
        results.append(masscan_result)

    return results


async def _run_subfinder(target: str, timeout: int = 120) -> ScanResult:
    """Run subfinder for subdomain discovery."""
    outfile = os.path.join(SCAN_OUTPUT_DIR, f"subfinder_{target.replace('/', '_')}_{os.getpid()}.txt")
    cmd = ["subfinder", "-d", target, "-o", outfile, "-silent"]
    rc, stdout, stderr = await _run_cmd(cmd, timeout)
    raw = ""
    if os.path.exists(outfile):
        with open(outfile) as f:
            raw = f.read()
    return ScanResult(
        scanner="subfinder", target=target, success=(rc == 0),
        raw_output=raw or stdout, output_file=outfile,
        error=stderr if rc != 0 else "", return_code=rc,
    )


def available_scanners() -> dict[str, bool]:
    """Check which scanners are available on the system."""
    tools = {
        "nmap": "nmap",
        "masscan": "masscan",
        "nuclei": "nuclei",
        "openvas": "gvm-cli",
        "zap": "zap-cli",
        "nikto": "nikto",
    }
    return {name: _check_tool(binary) for name, binary in tools.items()}
