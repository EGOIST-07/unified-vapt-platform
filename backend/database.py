"""MySQL database connection and query helpers for VAPT Dashboard."""

import os
from contextlib import contextmanager
from datetime import datetime
from typing import Optional

import time

import mysql.connector
from mysql.connector import pooling

import logging
_logger = logging.getLogger(__name__)

DB_CONFIG = {
    "host": os.getenv("MYSQL_HOST", "localhost"),
    "port": int(os.getenv("MYSQL_PORT", 3306)),
    "user": os.getenv("MYSQL_USER", "vapt_user"),
    "password": os.getenv("MYSQL_PASSWORD", "vapt_password"),
    "database": os.getenv("MYSQL_DATABASE", "vapt_dashboard"),
}

_pool = None
_schema_ensured = False


def _ensure_schema_updates(pool):
    """Apply lightweight schema updates needed by newer app versions."""
    global _schema_ensured
    if _schema_ensured:
        return

    conn = pool.get_connection()
    try:
        cur = conn.cursor()
        # scans.task_id
        cur.execute("SHOW COLUMNS FROM scans LIKE 'task_id'")
        if cur.fetchone() is None:
            cur.execute("ALTER TABLE scans ADD COLUMN task_id VARCHAR(255) DEFAULT NULL")
            _logger.info("Added scans.task_id column")

        # scans.scan_error
        cur.execute("SHOW COLUMNS FROM scans LIKE 'scan_error'")
        if cur.fetchone() is None:
            cur.execute("ALTER TABLE scans ADD COLUMN scan_error TEXT DEFAULT NULL AFTER scan_progress")
            _logger.info("Added scans.scan_error column")

        # scans.scan_progress
        cur.execute("SHOW COLUMNS FROM scans LIKE 'scan_progress'")
        if cur.fetchone() is None:
            cur.execute(
                "ALTER TABLE scans ADD COLUMN scan_progress INT NOT NULL DEFAULT 0 "
                "AFTER scan_status"
            )
            _logger.info("Added scans.scan_progress column")

        # scans.scan_status enum compatibility for older persisted schemas.
        # Some long-lived volumes still miss 'cancelled', causing 500 on cancel API.
        cur.execute("SHOW COLUMNS FROM scans LIKE 'scan_status'")
        scan_status_col = cur.fetchone()
        if scan_status_col is not None:
            enum_type = scan_status_col[1] if len(scan_status_col) > 1 else ""
            if "'cancelled'" not in str(enum_type):
                cur.execute(
                    "ALTER TABLE scans MODIFY COLUMN scan_status "
                    "ENUM('pending','running','completed','failed','cancelled') "
                    "DEFAULT 'pending'"
                )
                _logger.info("Updated scans.scan_status enum to include 'cancelled'")

        # ports.scan_id
        cur.execute("SHOW COLUMNS FROM ports LIKE 'scan_id'")
        if cur.fetchone() is None:
            cur.execute("ALTER TABLE ports ADD COLUMN scan_id INT DEFAULT NULL AFTER asset_id")
            _logger.info("Added ports.scan_id column")

        # services.scan_id
        cur.execute("SHOW COLUMNS FROM services LIKE 'scan_id'")
        if cur.fetchone() is None:
            cur.execute("ALTER TABLE services ADD COLUMN scan_id INT DEFAULT NULL AFTER asset_id")
            _logger.info("Added services.scan_id column")

        # vulnerabilities.scan_id
        cur.execute("SHOW COLUMNS FROM vulnerabilities LIKE 'scan_id'")
        if cur.fetchone() is None:
            cur.execute("ALTER TABLE vulnerabilities ADD COLUMN scan_id INT DEFAULT NULL AFTER asset_id")
            _logger.info("Added vulnerabilities.scan_id column")

        # best-effort index creation for scan_progress
        cur.execute("SHOW INDEX FROM scans WHERE Key_name='idx_scan_progress'")
        if cur.fetchone() is None:
            cur.execute("CREATE INDEX idx_scan_progress ON scans (scan_progress)")
            _logger.info("Added scans.idx_scan_progress index")

        # best-effort index creation for assets.asset_name
        cur.execute("SHOW INDEX FROM assets WHERE Key_name='idx_asset_name'")
        if cur.fetchone() is None:
            cur.execute("CREATE INDEX idx_asset_name ON assets (asset_name)")
            _logger.info("Added assets.idx_asset_name index")

        # Best-effort orphan cleanup: only fail scans that have truly gone stale.
        # This function runs once per process and must not touch fresh/pending scans.
        cur.execute(
            "UPDATE scans SET scan_status='failed', "
            "scan_error='Scan interrupted: worker unavailable for an extended period', "
            "completed_at=NOW() "
            "WHERE scan_status='running' "
            "AND started_at IS NOT NULL "
            "AND completed_at IS NULL "
            "AND started_at < (NOW() - INTERVAL 30 MINUTE)"
        )
        stale = cur.rowcount
        if stale:
            _logger.info("Marked %d stale running scan(s) as failed on startup", stale)

        conn.commit()
        _schema_ensured = True
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def _get_pool():
    global _pool
    if _pool is not None:
        return _pool
    for attempt in range(30):
        try:
            _pool = pooling.MySQLConnectionPool(
                pool_name="vapt_pool",
                pool_size=10,
                pool_reset_session=True,
                **DB_CONFIG,
            )
            _ensure_schema_updates(_pool)
            _logger.info("Database pool created successfully")
            return _pool
        except mysql.connector.Error as e:
            _logger.warning("DB connect attempt %d/30 failed: %s", attempt + 1, e)
            time.sleep(2)
    raise RuntimeError("Could not connect to MySQL after 30 attempts")


@contextmanager
def get_connection():
    conn = _get_pool().get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def dict_row(cursor):
    """Return all rows as list of dicts."""
    columns = [col[0] for col in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def dict_one(cursor):
    """Return single row as dict or None."""
    columns = [col[0] for col in cursor.description]
    row = cursor.fetchone()
    return dict(zip(columns, row)) if row else None


# ─── Assets ────────────────────────────────────────────────────────────────────

def create_asset(asset_name: str, asset_type: str, owner: str = None) -> int:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO assets (asset_name, asset_type, owner)
               VALUES (%s, %s, %s)
               ON DUPLICATE KEY UPDATE
                 owner = COALESCE(VALUES(owner), owner)""",
            (asset_name, asset_type, owner),
        )
        if cur.lastrowid:
            return cur.lastrowid
        cur.execute("SELECT id FROM assets WHERE asset_name=%s AND asset_type=%s",
                    (asset_name, asset_type))
        return cur.fetchone()[0]


def get_asset(asset_id: int) -> Optional[dict]:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM assets WHERE id=%s", (asset_id,))
        return dict_one(cur)


def get_assets(asset_type: str = None, search: str = None, limit: int = 100, offset: int = 0) -> list:
    with get_connection() as conn:
        cur = conn.cursor()
        query = "SELECT * FROM assets WHERE 1=1"
        params = []
        if asset_type:
            query += " AND asset_type=%s"
            params.append(asset_type)
        if search:
            query += " AND asset_name LIKE %s"
            params.append(f"%{search}%")
        query += " ORDER BY risk_score DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        cur.execute(query, params)
        return dict_row(cur)


def update_asset_risk(asset_id: int, risk_score: int):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE assets SET risk_score=%s WHERE id=%s",
                    (risk_score, asset_id))


def delete_asset(asset_id: int):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM assets WHERE id=%s", (asset_id,))


def count_assets() -> dict:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """SELECT asset_type, COUNT(*) as cnt FROM assets
               GROUP BY asset_type""")
        rows = dict_row(cur)
        result = {r["asset_type"]: r["cnt"] for r in rows}
        cur.execute("SELECT COUNT(*) as total FROM assets")
        result["total"] = cur.fetchone()[0]
        return result


# ─── Scans ─────────────────────────────────────────────────────────────────────

def create_scan(asset_id: int, scan_type: str) -> int:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO scans (asset_id, scan_type, scan_status, scan_progress, scan_error)
               VALUES (%s, %s, 'pending', 0, NULL)""",
            (asset_id, scan_type),
        )
        return cur.lastrowid


def update_scan(scan_id: int, **fields):
    allowed = {"scan_status", "scan_progress", "scan_error", "started_at", "completed_at", "task_id"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return
    with get_connection() as conn:
        cur = conn.cursor()
        set_clause = ", ".join(f"{k}=%s" for k in updates)
        cur.execute(f"UPDATE scans SET {set_clause} WHERE id=%s",
                    [*updates.values(), scan_id])


def update_scan_task_id(scan_id: int, task_id: str):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE scans SET task_id=%s WHERE id=%s", (task_id, scan_id))


def get_scan(scan_id: int) -> Optional[dict]:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM scans WHERE id=%s", (scan_id,))
        return dict_one(cur)


def get_scans(asset_id: int = None, scan_status: str = None,
              limit: int = 50, offset: int = 0) -> list:
    with get_connection() as conn:
        cur = conn.cursor()
        query = """SELECT s.*, a.asset_name
                   FROM scans s
                   LEFT JOIN assets a ON s.asset_id = a.id
                   WHERE 1=1"""
        params = []
        if asset_id:
            query += " AND s.asset_id=%s"
            params.append(asset_id)
        if scan_status:
            query += " AND s.scan_status=%s"
            params.append(scan_status)
        query += " ORDER BY s.id DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        cur.execute(query, params)
        return dict_row(cur)


# ─── Ports ─────────────────────────────────────────────────────────────────────

def create_port(asset_id: int, port_number: int, state: str = "open", scan_id: int = None) -> int:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO ports (asset_id, scan_id, port_number, state)
               VALUES (%s, %s, %s, %s)
               ON DUPLICATE KEY UPDATE state=VALUES(state), scan_id=COALESCE(VALUES(scan_id), scan_id)""",
            (asset_id, scan_id, port_number, state),
        )
        if cur.lastrowid:
            return cur.lastrowid
        cur.execute(
            "SELECT id FROM ports WHERE asset_id=%s AND port_number=%s",
            (asset_id, port_number))
        return cur.fetchone()[0]


def get_ports(asset_id: int) -> list:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM ports WHERE asset_id=%s ORDER BY port_number",
            (asset_id,))
        return dict_row(cur)


# ─── Services ─────────────────────────────────────────────────────────────────

def create_service(asset_id: int, port: int, protocol: str = "tcp",
                   service_name: str = None, version: str = None, scan_id: int = None) -> int:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO services
               (asset_id, scan_id, port, protocol, service_name, version)
               VALUES (%s, %s, %s, %s, %s, %s)
               ON DUPLICATE KEY UPDATE
                 service_name=VALUES(service_name),
                 version=VALUES(version),
                 scan_id=COALESCE(VALUES(scan_id), scan_id)""",
            (asset_id, scan_id, port, protocol, service_name, version),
        )
        if cur.lastrowid:
            return cur.lastrowid
        cur.execute(
            "SELECT id FROM services WHERE asset_id=%s AND port=%s AND protocol=%s",
            (asset_id, port, protocol))
        return cur.fetchone()[0]


def get_services(asset_id: int) -> list:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM services WHERE asset_id=%s ORDER BY port", (asset_id,))
        return dict_row(cur)


# ─── Vulnerabilities ──────────────────────────────────────────────────────────

def create_vulnerability(asset_id: int, vulnerability_name: str,
                         severity: str, service_id: int = None,
                         description: str = None, cve_id: str = None,
                         remediation: str = None, scan_id: int = None) -> int:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO vulnerabilities
               (asset_id, scan_id, service_id, vulnerability_name, description,
                severity, cve_id, remediation)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (asset_id, scan_id, service_id, vulnerability_name, description,
             severity, cve_id, remediation),
        )
        return cur.lastrowid


def get_vulnerabilities(asset_id: int = None, severity: str = None,
                        scan_id: int = None,
                        limit: int = 100, offset: int = 0) -> list:
    with get_connection() as conn:
        cur = conn.cursor()
        query = (
            """SELECT v.*, s.port, s.protocol, s.service_name, s.version
               FROM vulnerabilities v
               LEFT JOIN services s ON v.service_id = s.id
               WHERE 1=1"""
        )
        params = []
        if asset_id:
            query += " AND v.asset_id=%s"; params.append(asset_id)
        if severity:
            query += " AND v.severity=%s"; params.append(severity)
        if scan_id:
            query += " AND v.scan_id=%s"; params.append(scan_id)
        query += (
            " ORDER BY FIELD(v.severity,'critical','high','medium','low','info'),"
            " v.discovered_at DESC"
        )
        query += " LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        cur.execute(query, params)
        return dict_row(cur)


def severity_counts(asset_id: int = None) -> dict:
    with get_connection() as conn:
        cur = conn.cursor()
        query = "SELECT severity, COUNT(*) as cnt FROM vulnerabilities"
        params = []
        if asset_id:
            query += " WHERE asset_id=%s"
            params.append(asset_id)
        else:
            query += " WHERE 1=1"
        query += " GROUP BY severity"
        cur.execute(query, params)
        rows = dict_row(cur)
        return {r["severity"]: r["cnt"] for r in rows}


def vulnerability_trends(days: int = 30) -> list:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """SELECT DATE(discovered_at) as date, severity, COUNT(*) as cnt
               FROM vulnerabilities
               WHERE discovered_at >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
               GROUP BY DATE(discovered_at), severity
               ORDER BY date""",
            (days,))
        return dict_row(cur)


def top_vulnerable_assets(limit: int = 10) -> list:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """SELECT a.id, a.asset_name, a.asset_type, a.risk_score,
                      COUNT(v.id) as vuln_count,
                      SUM(CASE WHEN v.severity='critical' THEN 1 ELSE 0 END) as critical_count,
                      SUM(CASE WHEN v.severity='high' THEN 1 ELSE 0 END) as high_count
               FROM assets a
               LEFT JOIN vulnerabilities v ON a.id = v.asset_id
               GROUP BY a.id
               ORDER BY critical_count DESC, high_count DESC, vuln_count DESC
               LIMIT %s""",
            (limit,))
        return dict_row(cur)


# ─── Dashboard Stats ──────────────────────────────────────────────────────────

def dashboard_stats() -> dict:
    with get_connection() as conn:
        cur = conn.cursor()
        stats = {}

        cur.execute("SELECT COUNT(*) FROM assets")
        stats["total_assets"] = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM vulnerabilities")
        stats["open_vulnerabilities"] = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM scans WHERE scan_status='running'")
        stats["active_scans"] = cur.fetchone()[0]

        cur.execute("SELECT COUNT(*) FROM ports WHERE state='open'")
        stats["open_ports"] = cur.fetchone()[0]

        cur.execute(
            """SELECT COUNT(*) FROM vulnerabilities
               WHERE severity='critical'""")
        stats["critical_vulns"] = cur.fetchone()[0]

        cur.execute("SELECT AVG(risk_score) FROM assets")
        avg = cur.fetchone()[0]
        stats["avg_risk_score"] = float(avg) if avg else 0.0

        return stats


def calculate_risk_score(asset_id: int) -> int:
    """Calculate risk score for an asset based on its vulnerabilities."""
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """SELECT severity, COUNT(*) as cnt FROM vulnerabilities
               WHERE asset_id=%s
               GROUP BY severity""",
            (asset_id,))
        rows = dict_row(cur)

    counts = {r["severity"]: int(r["cnt"]) for r in rows}
    critical = counts.get("critical", 0)
    high = counts.get("high", 0)
    medium = counts.get("medium", 0)
    low = counts.get("low", 0)

    weighted_total = (critical * 10) + (high * 7) + (medium * 4) + (low * 1)
    vuln_total = critical + high + medium + low
    if vuln_total <= 0:
        score = 0
    else:
        max_possible = vuln_total * 10
        score = int(round((weighted_total / max_possible) * 100))
        score = max(0, min(score, 100))

    update_asset_risk(asset_id, score)
    return score


# ─── Per-scan queries ───────────────────────────────────────────────────────────

def get_ports_by_scan(scan_id: int) -> list:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM ports WHERE scan_id=%s ORDER BY port_number",
            (scan_id,))
        return dict_row(cur)


def get_services_by_scan(scan_id: int) -> list:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM services WHERE scan_id=%s ORDER BY port",
            (scan_id,))
        return dict_row(cur)


def get_vulnerabilities_by_scan(scan_id: int) -> list:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """SELECT v.*, s.port, s.protocol, s.service_name, s.version
               FROM vulnerabilities v
               LEFT JOIN services s ON v.service_id = s.id
               WHERE v.scan_id=%s
               ORDER BY FIELD(v.severity,'critical','high','medium','low','info'),
                        v.discovered_at DESC""",
            (scan_id,))
        rows = dict_row(cur)
        if rows:
            return rows

        # Legacy fallback: older records may have NULL scan_id.
        scan = get_scan(scan_id)
        if not scan:
            return []

        asset_id = scan["asset_id"]
        started_at = scan.get("started_at")
        completed_at = scan.get("completed_at")

        query = (
            """SELECT v.*, s.port, s.protocol, s.service_name, s.version
               FROM vulnerabilities v
               LEFT JOIN services s ON v.service_id = s.id
               WHERE v.asset_id=%s
                 AND v.scan_id IS NULL"""
        )
        params = [asset_id]

        if started_at and completed_at:
            query += (
                " AND v.discovered_at BETWEEN "
                "(%s - INTERVAL 30 MINUTE) AND (%s + INTERVAL 30 MINUTE)"
            )
            params.extend([started_at, completed_at])
        elif started_at:
            query += " AND v.discovered_at >= (%s - INTERVAL 30 MINUTE)"
            params.append(started_at)
        elif completed_at:
            query += " AND v.discovered_at <= (%s + INTERVAL 30 MINUTE)"
            params.append(completed_at)

        query += (
            " ORDER BY FIELD(v.severity,'critical','high','medium','low','info'),"
            " v.discovered_at DESC LIMIT 500"
        )
        cur.execute(query, params)
        return dict_row(cur)
