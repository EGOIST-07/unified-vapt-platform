"""Asset discovery using Subfinder and Amass."""

import asyncio
import logging
import os
import shutil
import re
import ipaddress

logger = logging.getLogger(__name__)

SCAN_OUTPUT_DIR = os.getenv("SCAN_OUTPUT_DIR", "/tmp/vapt_scans")
os.makedirs(SCAN_OUTPUT_DIR, exist_ok=True)
MAX_VERIFY_CANDIDATES = int(os.getenv("DISCOVERY_MAX_VERIFY", "1500"))


async def _run_cmd(cmd: list[str], timeout: int = 300) -> tuple[int, str, str]:
    logger.info("Executing discovery command: %s", " ".join(cmd))
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
        logger.warning("Discovery command timed out after %ss: %s", timeout, " ".join(cmd))
        return -1, "", "Discovery timed out"
    decoded_stdout = stdout.decode(errors="replace")
    decoded_stderr = stderr.decode(errors="replace")
    logger.info(
        "Command finished rc=%s stdout_lines=%s stderr_lines=%s",
        proc.returncode,
        len(decoded_stdout.splitlines()),
        len(decoded_stderr.splitlines()),
    )
    if decoded_stderr.strip():
        logger.debug("Command stderr sample: %s", decoded_stderr[:800])
    return proc.returncode, decoded_stdout, decoded_stderr


def _normalize_domain(value: str) -> str:
    return value.strip().lower().rstrip(".")


def _extract_subdomains_from_text(text: str, apex_domain: str) -> set[str]:
    """Extract likely subdomains from command stdout/stderr text."""
    if not text:
        return set()

    apex = _normalize_domain(apex_domain)
    found: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip().lower().rstrip(".")
        if not line or " " in line or line.startswith("["):
            continue
        if _is_valid_domain(line) and (line == apex or line.endswith(f".{apex}")):
            found.add(line)
    return found


# ─── Subfinder ─────────────────────────────────────────────────────────────────

async def run_subfinder(domain: str, timeout: int = 300) -> list[str]:
    """Discover subdomains using Subfinder."""
    if not shutil.which("subfinder"):
        logger.warning("subfinder not installed, skipping")
        return []

    domain = _normalize_domain(domain)
    outfile = os.path.join(SCAN_OUTPUT_DIR, f"subfinder_{domain}_{os.getpid()}.txt")
    cmd = ["subfinder", "-d", domain, "-silent", "-o", outfile]

    rc, stdout, stderr = await _run_cmd(cmd, timeout)

    subdomains = set()
    if os.path.exists(outfile):
        with open(outfile) as f:
            for line in f:
                sub = line.strip()
                if sub and _is_valid_domain(sub):
                    subdomains.add(sub)
    subdomains.update(_extract_subdomains_from_text(stdout, domain))
    subdomains.update(_extract_subdomains_from_text(stderr, domain))

    if rc != 0:
        logger.warning("Subfinder exited with rc=%s for %s", rc, domain)

    logger.info("Subfinder found %d subdomains for %s", len(subdomains), domain)
    return sorted(subdomains)


# ─── Amass ─────────────────────────────────────────────────────────────────────

async def run_amass(domain: str, passive: bool = True,
                    timeout: int = 600) -> list[str]:
    """Discover subdomains using Amass."""
    if not shutil.which("amass"):
        logger.warning("amass not installed, skipping")
        return []

    domain = _normalize_domain(domain)
    outfile = os.path.join(SCAN_OUTPUT_DIR, f"amass_{domain}_{os.getpid()}.txt")
    cmd = ["amass", "enum", "-d", domain, "-o", outfile, "-silent"]
    if passive:
        cmd.append("-passive")

    rc, stdout, stderr = await _run_cmd(cmd, timeout)

    subdomains = set()
    if os.path.exists(outfile):
        with open(outfile) as f:
            for line in f:
                sub = line.strip()
                if sub and _is_valid_domain(sub):
                    subdomains.add(sub)

    subdomains.update(_extract_subdomains_from_text(stdout, domain))
    subdomains.update(_extract_subdomains_from_text(stderr, domain))

    if rc != 0:
        logger.warning("Amass exited with rc=%s for %s", rc, domain)

    logger.info("Amass found %d subdomains for %s", len(subdomains), domain)
    return sorted(subdomains)


# ─── DNS Resolution ───────────────────────────────────────────────────────────

async def resolve_domain(domain: str, timeout: int = 5) -> list[str]:
    """Resolve a domain to A/AAAA addresses using dig."""
    if not shutil.which("dig"):
        logger.warning("dig not installed, skipping resolution")
        return []

    domain = _normalize_domain(domain)
    rc_a, stdout_a, _ = await _run_cmd(["dig", "+short", domain, "A"], timeout=timeout)
    rc_aaaa, stdout_aaaa, _ = await _run_cmd(["dig", "+short", domain, "AAAA"], timeout=timeout)

    ips = []
    for line in (stdout_a + "\n" + stdout_aaaa).splitlines():
        value = line.strip()
        if not value:
            continue
        try:
            ipaddress.ip_address(value)
            ips.append(value)
        except ValueError:
            continue

    if rc_a != 0 and rc_aaaa != 0:
        logger.debug("dig returned non-zero for %s (A=%s AAAA=%s)", domain, rc_a, rc_aaaa)
    return ips


async def has_dns_record(domain: str, timeout: int = 5) -> tuple[bool, list[str]]:
    """Return whether a domain resolves to A/AAAA/CNAME and associated IPs."""
    ips = await resolve_domain(domain, timeout=timeout)
    if ips:
        return True, ips

    if not shutil.which("dig"):
        return False, []

    rc_cname, stdout_cname, _ = await _run_cmd(
        ["dig", "+short", _normalize_domain(domain), "CNAME"], timeout=timeout
    )
    cname_targets = [line.strip().rstrip(".") for line in stdout_cname.splitlines() if line.strip()]
    if rc_cname == 0 and cname_targets:
        return True, []

    return False, []


async def reverse_dns(ip: str) -> str | None:
    """Reverse DNS lookup for an IP."""
    if not shutil.which("dig"):
        return None

    rc, stdout, _ = await _run_cmd(["dig", "+short", "-x", ip], timeout=15)
    result = stdout.strip().rstrip(".")
    return result if result else None


# ─── Combined Discovery ───────────────────────────────────────────────────────

async def discover_assets(domain: str) -> dict:
    """Run full asset discovery: subdomains, DNS resolution, reverse DNS.

    Returns:
        {
            "domain": str,
            "subdomains": [{"name": str, "ips": [str]}],
            "total_subdomains": int,
            "total_ips": int,
        }
    """
    # Run both tools concurrently
    subfinder_subs, amass_subs = await asyncio.gather(
        run_subfinder(domain),
        run_amass(domain),
    )

    # Merge and deduplicate
    all_subs = sorted(set(subfinder_subs) | set(amass_subs))
    logger.info("Total unique subdomains for %s: %d", domain, len(all_subs))

    # Resolve IPs for each subdomain (batched to avoid overwhelming DNS)
    results = []
    all_ips = set()
    batch_size = 20

    for i in range(0, len(all_subs), batch_size):
        batch = all_subs[i:i + batch_size]
        resolutions = await asyncio.gather(
            *[resolve_domain(sub) for sub in batch]
        )
        for sub, ips in zip(batch, resolutions):
            results.append({"name": sub, "ips": ips})
            all_ips.update(ips)

    # Also resolve the main domain
    main_ips = await resolve_domain(domain)
    all_ips.update(main_ips)

    return {
        "domain": domain,
        "domain_ips": main_ips,
        "subdomains": results,
        "total_subdomains": len(all_subs),
        "total_ips": len(all_ips),
    }


async def discover_subdomains(domain: str) -> dict:
    """Enumerate and verify subdomains only (no scanning).

    Pipeline:
      subfinder + amass -> deduplicate -> DNS verification with dig
    """
    domain = _normalize_domain(domain)
    if not _is_valid_domain(domain):
        raise ValueError(f"Invalid domain: {domain}")

    subfinder_subs, amass_subs = await asyncio.gather(
        run_subfinder(domain, timeout=240),
        run_amass(domain, timeout=420),
    )

    candidates = sorted(set(subfinder_subs) | set(amass_subs))
    if len(candidates) > MAX_VERIFY_CANDIDATES:
        logger.warning(
            "Discovery candidates for %s exceeded limit (%d > %d), truncating verification set",
            domain,
            len(candidates),
            MAX_VERIFY_CANDIDATES,
        )
        candidates = candidates[:MAX_VERIFY_CANDIDATES]
    logger.info(
        "Discovery results for %s: subfinder=%d amass=%d merged=%d",
        domain,
        len(subfinder_subs),
        len(amass_subs),
        len(candidates),
    )

    verified: list[dict] = []
    semaphore = asyncio.Semaphore(80)

    async def _verify(subdomain: str) -> tuple[str, list[str]]:
        async with semaphore:
            is_valid, ips = await has_dns_record(subdomain, timeout=4)
            return subdomain, ips if is_valid else []

    tasks = [asyncio.create_task(_verify(subdomain)) for subdomain in candidates]
    for task in asyncio.as_completed(tasks):
        subdomain, ips = await task
        if ips:
            verified.append({"name": subdomain, "ips": ips})

    verified_names = sorted(entry["name"] for entry in verified)
    logger.info("Final validated subdomains for %s: %d", domain, len(verified_names))
    return {
        "domain": domain,
        "discovered_subdomains": verified_names,
        "verified_subdomains": verified,
        "total_discovered": len(candidates),
        "total_verified": len(verified_names),
    }


# ─── Helpers ───────────────────────────────────────────────────────────────────

def _is_valid_domain(value: str) -> bool:
    """Basic domain name validation."""
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, value))


def available_discovery_tools() -> dict[str, bool]:
    return {
        "subfinder": shutil.which("subfinder") is not None,
        "amass": shutil.which("amass") is not None,
        "dig": shutil.which("dig") is not None,
    }
