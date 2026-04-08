"""VAPT Dashboard — FastAPI application with all API routes."""

import asyncio
import ipaddress
import logging
import os
import re
from uuid import uuid4
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from fastapi.responses import Response

import database as db
import scanner
import discovery
import report
import auth
from auth import get_current_user
from tasks import execute_scan
from tasks import discover_subdomains_task
from celery_app import celery_app

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("VAPT Dashboard starting up")
    auth.ensure_admin()
    yield
    logger.info("VAPT Dashboard shutting down")


app = FastAPI(
    title="VAPT Dashboard API",
    description="Vulnerability Assessment & Penetration Testing Dashboard",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("CORS_ORIGIN", "http://localhost:3000")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Request / Response Models ─────────────────────────────────────────────────

class AssetCreate(BaseModel):
    asset_name: str = Field(..., min_length=1, max_length=255)
    asset_type: str = Field(..., pattern="^(domain|subdomain|ip|cidr)$")
    owner: Optional[str] = None

class ScanCreate(BaseModel):
    asset_id: int
    scan_type: str = Field(..., pattern="^(quick|network|full)$")

class DiscoverRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=255)

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=255)
    password: str = Field(..., min_length=1, max_length=255)


# ─── Authentication ────────────────────────────────────────────────────────────

@app.post("/api/auth/login")
def login(body: LoginRequest):
    user = auth.authenticate_user(body.username, body.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = auth.create_access_token(user["username"])
    return {"access_token": token, "token_type": "bearer", "username": user["username"]}


@app.get("/api/auth/me")
def me(current_user: dict = Depends(get_current_user)):
    return current_user


@app.post("/api/auth/logout")
def logout(current_user: dict = Depends(get_current_user)):
    return {"message": "Logged out successfully"}


# ─── Health ────────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health(current_user: dict = Depends(get_current_user)):
    return {
        "status": "ok",
        "scanners": scanner.available_scanners(),
        "discovery_tools": discovery.available_discovery_tools(),
    }


# ─── Assets ───────────────────────────────────────────────────────────────────

@app.post("/api/assets", status_code=201)
def create_asset(body: AssetCreate, current_user: dict = Depends(get_current_user)):
    name = body.asset_name.strip()
    atype = body.asset_type

    # Validate based on asset type
    _DOMAIN_RE = re.compile(
        r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$'
    )
    if atype in ('domain', 'subdomain'):
        if not _DOMAIN_RE.match(name):
            raise HTTPException(422, f"Invalid {atype}: '{name}' is not a valid domain name")
    elif atype == 'ip':
        try:
            ipaddress.ip_address(name)
        except ValueError:
            raise HTTPException(422, f"Invalid IP address: '{name}'")
    elif atype == 'cidr':
        try:
            ipaddress.ip_network(name, strict=False)
        except ValueError:
            raise HTTPException(422, f"Invalid CIDR range: '{name}'")

    asset_id = db.create_asset(
        asset_name=name, asset_type=atype,
        owner=body.owner,
    )
    return db.get_asset(asset_id)


@app.get("/api/assets")
def list_assets(
    asset_type: Optional[str] = None,
    search: Optional[str] = Query(None, min_length=1, max_length=255),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user),
):
    return db.get_assets(asset_type=asset_type, search=search, limit=limit, offset=offset)


@app.get("/api/assets/{asset_id}")
def get_asset(asset_id: int, current_user: dict = Depends(get_current_user)):
    asset = db.get_asset(asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    return asset


@app.delete("/api/assets/{asset_id}", status_code=204)
def delete_asset(asset_id: int, current_user: dict = Depends(get_current_user)):
    asset = db.get_asset(asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    db.delete_asset(asset_id)


@app.get("/api/assets/{asset_id}/ports")
def asset_ports(asset_id: int, current_user: dict = Depends(get_current_user)):
    asset = db.get_asset(asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    return db.get_ports(asset_id)


@app.get("/api/assets/{asset_id}/services")
def asset_services(asset_id: int, current_user: dict = Depends(get_current_user)):
    asset = db.get_asset(asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    return db.get_services(asset_id)


@app.get("/api/assets/{asset_id}/vulnerabilities")
def asset_vulnerabilities(asset_id: int, current_user: dict = Depends(get_current_user)):
    asset = db.get_asset(asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    return db.get_vulnerabilities(asset_id=asset_id)


# ─── Scans ─────────────────────────────────────────────────────────────────────

@app.post("/api/scans", status_code=201)
def create_scan(body: ScanCreate, current_user: dict = Depends(get_current_user)):
    asset = db.get_asset(body.asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")

    scan_id = db.create_scan(
        asset_id=body.asset_id, scan_type=body.scan_type,
    )
    task_id = uuid4().hex
    db.update_scan_task_id(scan_id, task_id)
    execute_scan.apply_async((scan_id, body.asset_id, body.scan_type), task_id=task_id)
    return {"id": scan_id, "scan_status": "pending", "scan_type": body.scan_type}


@app.get("/api/scans")
def list_scans(
    asset_id: Optional[int] = None,
    scan_status: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user),
):
    return db.get_scans(asset_id=asset_id, scan_status=scan_status, limit=limit, offset=offset)


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int, current_user: dict = Depends(get_current_user)):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@app.post("/api/scans/{scan_id}/cancel")
def cancel_scan(scan_id: int, current_user: dict = Depends(get_current_user)):
    """Cancel a running scan by revoking its Celery task."""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan["scan_status"] not in ("pending", "running"):
        raise HTTPException(400, "Scan is not running")
    task_id = scan.get("task_id")
    if task_id:
        celery_app.control.revoke(task_id, terminate=True)
    db.update_scan(scan_id, scan_status="cancelled", scan_progress=100, completed_at=datetime.utcnow())
    return {"id": scan_id, "scan_status": "cancelled"}


# ─── Vulnerabilities ──────────────────────────────────────────────────────────

@app.get("/api/vulnerabilities")
def list_vulnerabilities(
    asset_id: Optional[int] = None,
    severity: Optional[str] = None,
    scan_id: Optional[int] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user),
):
    return db.get_vulnerabilities(
        asset_id=asset_id, severity=severity,
        scan_id=scan_id,
        limit=limit, offset=offset,
    )


@app.get("/api/scans/{scan_id}/recommendations")
def scan_recommendations(scan_id: int, current_user: dict = Depends(get_current_user)):
    """Return automated security recommendations for a specific scan."""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    vulnerabilities = db.get_vulnerabilities_by_scan(scan_id)
    services = db.get_services_by_scan(scan_id)
    recommendations = report.build_security_recommendations(vulnerabilities, services)

    return {
        "scan_id": scan_id,
        "asset_id": scan["asset_id"],
        "recommendations": recommendations,
    }


# ─── Discovery ─────────────────────────────────────────────────────────────────

@app.post("/api/discover")
def discover(body: DiscoverRequest, current_user: dict = Depends(get_current_user)):
    """Backward-compatible alias for dedicated subdomain discovery."""
    domain = body.domain.strip().lower().rstrip(".")
    if not discovery._is_valid_domain(domain):
        raise HTTPException(422, "Invalid domain format")
    task = discover_subdomains_task.delay(domain)
    return {"domain": domain, "task_id": task.id, "status": "pending"}


@app.post("/api/discover-subdomains")
def discover_subdomains_endpoint(body: DiscoverRequest, current_user: dict = Depends(get_current_user)):
    """Start background subdomain enumeration for a domain."""
    domain = body.domain.strip().lower().rstrip(".")
    if not discovery._is_valid_domain(domain):
        raise HTTPException(422, "Invalid domain format")
    task = discover_subdomains_task.delay(domain)
    return {"domain": domain, "task_id": task.id, "status": "pending"}


@app.get("/api/discover-subdomains/{task_id}")
def discover_subdomains_status(task_id: str, current_user: dict = Depends(get_current_user)):
    """Get status/results for a background subdomain discovery task."""
    result = celery_app.AsyncResult(task_id)
    if result.failed():
        return {"task_id": task_id, "status": "failed", "error": str(result.result)}
    if not result.ready():
        return {"task_id": task_id, "status": "pending"}

    payload = result.result if isinstance(result.result, dict) else {"result": result.result}
    status = payload.get("status", "completed")
    subdomains = payload.get("subdomains") or payload.get("discovered_subdomains") or []
    return {"task_id": task_id, "status": status, "subdomains": subdomains, **payload}


# ─── Dashboard ─────────────────────────────────────────────────────────────────

@app.get("/api/dashboard/stats")
def dashboard_stats(current_user: dict = Depends(get_current_user)):
    return db.dashboard_stats()


@app.get("/api/dashboard/severity")
def severity_distribution(asset_id: Optional[int] = None, current_user: dict = Depends(get_current_user)):
    return db.severity_counts(asset_id=asset_id)


@app.get("/api/dashboard/trends")
def vulnerability_trends(days: int = Query(30, ge=1, le=365), current_user: dict = Depends(get_current_user)):
    return db.vulnerability_trends(days=days)


@app.get("/api/dashboard/top-assets")
def top_vulnerable_assets(limit: int = Query(10, ge=1, le=50), current_user: dict = Depends(get_current_user)):
    return db.top_vulnerable_assets(limit=limit)


@app.get("/api/dashboard/asset-counts")
def asset_counts(current_user: dict = Depends(get_current_user)):
    return db.count_assets()


# ─── Reports ──────────────────────────────────────────────────────────────────

@app.get("/api/report/{asset_id}")
def generate_report(asset_id: int, token: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    """Generate and download a PDF vulnerability report for an asset."""
    asset = db.get_asset(asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")

    scans = db.get_scans(asset_id=asset_id, limit=50)
    ports = db.get_ports(asset_id)
    services = db.get_services(asset_id)
    vulnerabilities = db.get_vulnerabilities(asset_id=asset_id, limit=500)

    pdf_bytes = report.generate_report(asset, scans, ports, services, vulnerabilities)

    filename = f"vapt_report_{asset['asset_name'].replace('/', '_')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/report/scan/{scan_id}")
def generate_scan_report(scan_id: int, token: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    """Generate and download a PDF vulnerability report for a specific scan."""
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    asset = db.get_asset(scan["asset_id"])
    if not asset:
        raise HTTPException(404, "Asset not found")

    ports = db.get_ports_by_scan(scan_id)
    services = db.get_services_by_scan(scan_id)
    vulnerabilities = db.get_vulnerabilities_by_scan(scan_id)

    if not vulnerabilities:
        logger.warning(
            "Scan %s has no scan-linked vulnerabilities. Falling back to asset-level lookup.",
            scan_id,
        )
        asset_vulns = db.get_vulnerabilities(asset_id=asset["id"], limit=1000)

        def _to_dt(value):
            if isinstance(value, datetime):
                return value
            if isinstance(value, str):
                try:
                    return datetime.fromisoformat(value.replace("Z", "+00:00"))
                except ValueError:
                    return None
            return None

        started_at = _to_dt(scan.get("started_at"))
        completed_at = _to_dt(scan.get("completed_at"))

        if (started_at or completed_at) and asset_vulns:
            lower = (started_at - timedelta(hours=2)) if started_at else None
            upper = (completed_at + timedelta(hours=2)) if completed_at else None
            filtered = []

            for vuln in asset_vulns:
                discovered_at = _to_dt(vuln.get("discovered_at"))
                if discovered_at is None:
                    continue
                if lower and discovered_at < lower:
                    continue
                if upper and discovered_at > upper:
                    continue
                filtered.append(vuln)

            vulnerabilities = filtered
        else:
            vulnerabilities = asset_vulns

        logger.info(
            "Scan %s fallback selected %d vulnerabilities for report.",
            scan_id,
            len(vulnerabilities),
        )

    pdf_bytes = report.generate_report(asset, [scan], ports, services, vulnerabilities)

    filename = f"vapt_report_scan{scan_id}_{asset['asset_name'].replace('/', '_')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ─── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", 8000)),
        reload=os.getenv("ENV", "development") == "development",
    )
