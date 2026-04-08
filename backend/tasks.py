"""Celery tasks for VAPT Dashboard scan execution."""

import asyncio
import logging
import os
from datetime import datetime

from celery_app import celery_app
import database as db
import scanner
import parser
import discovery

logger = logging.getLogger(__name__)
DISCOVERY_TASK_TIMEOUT_S = int(os.getenv("DISCOVERY_TASK_TIMEOUT_S", "600"))


async def _run_scan(target: str, asset_type: str, scan_type: str):
    """Async helper: run the appropriate scan pipeline."""
    if scan_type == "quick":
        return await scanner.run_quick_scan(target, asset_type)
    elif scan_type == "network":
        return await scanner.run_network_scan(target, asset_type)
    elif scan_type == "full":
        return await scanner.run_full_scan(target, asset_type)
    else:
        return [await scanner.run_scan("nmap", target)]


def _scan_timeout_seconds(scan_type: str) -> int:
    """Upper bound for scan task runtime to avoid indefinite running states."""
    if scan_type == "quick":
        return 420
    if scan_type == "network":
        return 480
    if scan_type == "full":
        return 1200
    return 600


def _stage_progress(scan_type: str) -> dict[str, int]:
    """Return stage percentage checkpoints for a scan type."""
    base = {
        "discovery": 20,
        "port_scanning": 40,
        "service_detection": 60,
        "vulnerability_scanning": 80,
        "report_generation": 100,
    }
    if scan_type == "quick":
        return {
            "discovery": 25,
            "port_scanning": 50,
            "service_detection": 70,
            "vulnerability_scanning": 90,
            "report_generation": 100,
        }
    return base


def _interpolate_progress(start: int, end: int, index: int, total: int) -> int:
    """Return interpolated integer progress for index/total within [start, end]."""
    if total <= 0:
        return start
    ratio = max(0.0, min(float(index) / float(total), 1.0))
    return int(round(start + ((end - start) * ratio)))


def _stop_reason(scan_id: int, asset_id: int) -> str | None:
    """Return a reason to stop processing when scan/asset state changed mid-run."""
    scan = db.get_scan(scan_id)
    if not scan:
        return "Scan no longer exists"
    if scan.get("scan_status") == "cancelled":
        return "Scan was cancelled"
    if db.get_asset(asset_id) is None:
        return "Asset was deleted while scan was running"
    return None


def _task_ownership_reason(scan_id: int, task_id: str | None) -> str | None:
    """Ensure only the currently linked task_id can execute a scan row."""
    if not task_id:
        return "Task id missing for scan"

    scan = db.get_scan(scan_id)
    if not scan:
        return "Scan no longer exists"

    expected_task_id = scan.get("task_id")
    if not expected_task_id:
        return "Scan has no active task id"

    if expected_task_id != task_id:
        return "Stale or superseded task execution blocked"

    return None


@celery_app.task(bind=True, name="execute_scan")
def execute_scan(self, scan_id: int, asset_id: int, scan_type: str):
    """Run a scan and store results (Celery task)."""
    task_id = getattr(self.request, "id", None)

    ownership_reason = _task_ownership_reason(scan_id, task_id)
    if ownership_reason:
        logger.warning(
            "Ignoring task %s for scan %s: %s",
            task_id,
            scan_id,
            ownership_reason,
        )
        return {
            "scan_id": scan_id,
            "status": "ignored",
            "reason": ownership_reason,
            "task_id": task_id,
        }

    asset = db.get_asset(asset_id)
    if not asset:
        db.update_scan(scan_id, scan_status="failed", scan_error="asset not found")
        return {"scan_id": scan_id, "status": "failed", "reason": "asset not found"}

    target = asset["asset_name"]
    asset_type = asset["asset_type"]

    stage = _stage_progress(scan_type)
    db.update_scan(
        scan_id,
        scan_status="running",
        scan_progress=stage["discovery"],
        scan_error=None,
        started_at=datetime.utcnow(),
    )

    try:
        timeout_s = _scan_timeout_seconds(scan_type)
        results = asyncio.run(
            asyncio.wait_for(_run_scan(target, asset_type, scan_type), timeout=timeout_s)
        )
        db.update_scan(scan_id, scan_progress=stage["port_scanning"])

        all_vulns = []
        total_results = max(len(results), 1)
        for idx, result in enumerate(results, start=1):
            ownership_reason = _task_ownership_reason(scan_id, task_id)
            if ownership_reason:
                logger.warning(
                    "Stopping task %s for scan %s: %s",
                    task_id,
                    scan_id,
                    ownership_reason,
                )
                return {
                    "scan_id": scan_id,
                    "status": "ignored",
                    "reason": ownership_reason,
                    "task_id": task_id,
                }

            reason = _stop_reason(scan_id, asset_id)
            if reason:
                db.update_scan(
                    scan_id,
                    scan_status="cancelled",
                    scan_progress=100,
                    scan_error=reason,
                    completed_at=datetime.utcnow(),
                )
                return {"scan_id": scan_id, "status": "cancelled", "reason": reason}

            # Keep progress moving across scanner phases.
            scanner_progress = _interpolate_progress(
                stage["port_scanning"],
                stage["service_detection"],
                idx,
                total_results,
            )
            db.update_scan(scan_id, scan_progress=scanner_progress)

            if not result.success:
                logger.warning(
                    "Scanner %s failed for %s: %s",
                    result.scanner, target, result.error,
                )
                continue

            parsed = parser.parse_scan_output(result.scanner, result.raw_output)

            services = parsed.get("services", [])
            vulnerabilities = parsed.get("vulnerabilities", [])

            item_total = max(len(services) + len(vulnerabilities), 1)
            item_index = 0
            service_start = max(scanner_progress, stage["service_detection"])
            item_end = stage["vulnerability_scanning"]

            for svc in services:
                ownership_reason = _task_ownership_reason(scan_id, task_id)
                if ownership_reason:
                    logger.warning(
                        "Stopping task %s for scan %s: %s",
                        task_id,
                        scan_id,
                        ownership_reason,
                    )
                    return {
                        "scan_id": scan_id,
                        "status": "ignored",
                        "reason": ownership_reason,
                        "task_id": task_id,
                    }

                reason = _stop_reason(scan_id, asset_id)
                if reason:
                    db.update_scan(
                        scan_id,
                        scan_status="cancelled",
                        scan_progress=100,
                        scan_error=reason,
                        completed_at=datetime.utcnow(),
                    )
                    return {"scan_id": scan_id, "status": "cancelled", "reason": reason}

                port_num = svc["port"]
                state = svc.get("state", "open")
                db.create_port(asset_id=asset_id, port_number=port_num, state=state, scan_id=scan_id)
                db.create_service(
                    asset_id=asset_id,
                    port=port_num,
                    protocol=svc.get("protocol", "tcp"),
                    service_name=svc.get("service", ""),
                    version=svc.get("version", ""),
                    scan_id=scan_id,
                )

                item_index += 1
                db.update_scan(
                    scan_id,
                    scan_progress=_interpolate_progress(service_start, item_end, item_index, item_total),
                )

            for vuln in vulnerabilities:
                ownership_reason = _task_ownership_reason(scan_id, task_id)
                if ownership_reason:
                    logger.warning(
                        "Stopping task %s for scan %s: %s",
                        task_id,
                        scan_id,
                        ownership_reason,
                    )
                    return {
                        "scan_id": scan_id,
                        "status": "ignored",
                        "reason": ownership_reason,
                        "task_id": task_id,
                    }

                reason = _stop_reason(scan_id, asset_id)
                if reason:
                    db.update_scan(
                        scan_id,
                        scan_status="cancelled",
                        scan_progress=100,
                        scan_error=reason,
                        completed_at=datetime.utcnow(),
                    )
                    return {"scan_id": scan_id, "status": "cancelled", "reason": reason}

                db.create_vulnerability(
                    asset_id=asset_id,
                    vulnerability_name=vuln["title"],
                    severity=vuln.get("severity", "info"),
                    description=vuln.get("description"),
                    cve_id=vuln.get("cve_id"),
                    remediation=vuln.get("remediation"),
                    scan_id=scan_id,
                )
                all_vulns.append(vuln)

                item_index += 1
                db.update_scan(
                    scan_id,
                    scan_progress=_interpolate_progress(service_start, item_end, item_index, item_total),
                )

        db.update_scan(scan_id, scan_progress=stage["vulnerability_scanning"])

        db.calculate_risk_score(asset_id)
        db.update_scan(
            scan_id,
            scan_status="completed",
            scan_progress=stage["report_generation"],
            scan_error=None,
            completed_at=datetime.utcnow(),
        )
        logger.info("Scan %d completed: %d vulnerabilities found", scan_id, len(all_vulns))
        return {"scan_id": scan_id, "status": "completed", "vulnerabilities": len(all_vulns)}

    except asyncio.TimeoutError:
        logger.exception("Scan %d timed out", scan_id)
        reason = f"Scan timed out after {_scan_timeout_seconds(scan_type)} seconds"
        db.update_scan(
            scan_id,
            scan_status="failed",
            scan_progress=100,
            scan_error=reason,
            completed_at=datetime.utcnow(),
        )
        return {"scan_id": scan_id, "status": "failed", "reason": reason}

    except Exception as e:
        logger.exception("Scan %d failed", scan_id)
        reason = str(e)
        db.update_scan(
            scan_id,
            scan_status="failed",
            scan_progress=100,
            scan_error=reason,
            completed_at=datetime.utcnow(),
        )
        return {"scan_id": scan_id, "status": "failed", "reason": reason}


@celery_app.task(bind=True, name="discover_subdomains_task")
def discover_subdomains_task(self, domain: str):
    """Run subdomain enumeration only and return reconnaissance results."""
    try:
        result = asyncio.run(
            asyncio.wait_for(
                discovery.discover_subdomains(domain),
                timeout=DISCOVERY_TASK_TIMEOUT_S,
            )
        )
        discovered = result.get("discovered_subdomains", [])

        return {
            "status": "completed",
            "domain": domain,
            "subdomains": discovered,
            "discovered_subdomains": discovered,
            "total_discovered": result.get("total_discovered", len(discovered)),
            "total_verified": result.get("total_verified", len(discovered)),
        }
    except asyncio.TimeoutError:
        reason = f"Discovery timed out after {DISCOVERY_TASK_TIMEOUT_S} seconds"
        logger.warning("Subdomain discovery timeout for %s", domain)
        return {
            "status": "failed",
            "domain": domain,
            "reason": reason,
        }
    except Exception as exc:
        logger.exception("Subdomain discovery failed for %s", domain)
        return {
            "status": "failed",
            "domain": domain,
            "reason": str(exc),
        }
