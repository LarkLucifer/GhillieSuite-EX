"""
ghilliesuite_ex/state/db.py
────────────────
Async SQLite state manager using aiosqlite.

Agents read from and write to this DB instead of passing raw tool output
around — which would rapidly blow out the LLM's context window.

The DB stores:
  • hosts      — live domains/IPs discovered during recon
  • endpoints  — crawled URLs with parameter info
  • findings   — confirmed or suspected vulnerabilities
  • cve_cache  — cached CVE lookups (avoid redundant NVD API calls)

Usage:
    async with StateDB(cfg.db_path) as db:
        await db.insert_host(host)
        hosts = await db.get_hosts()
"""

from __future__ import annotations

import json
from pathlib import Path

import aiosqlite

from .models import CVEResult, Endpoint, Finding, Host

# ── DDL ───────────────────────────────────────────────────────────────────────
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    domain       TEXT    NOT NULL UNIQUE,
    ip           TEXT    DEFAULT '',
    status_code  INTEGER DEFAULT 0,
    server       TEXT    DEFAULT '',
    tech_stack   TEXT    DEFAULT '',
    discovered_at TEXT   NOT NULL
);

CREATE TABLE IF NOT EXISTS endpoints (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT    NOT NULL UNIQUE,
    method      TEXT    DEFAULT 'GET',
    params      TEXT    DEFAULT '',
    source_tool TEXT    DEFAULT '',
    host_id     INTEGER REFERENCES hosts(id),
    found_at    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    tool              TEXT NOT NULL,
    target            TEXT NOT NULL,
    severity          TEXT NOT NULL,
    title             TEXT NOT NULL,
    evidence          TEXT DEFAULT '',
    reproducible_steps TEXT DEFAULT '',
    raw_output        TEXT DEFAULT '',
    timestamp         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cve_cache (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    keyword      TEXT NOT NULL,
    cve_id       TEXT NOT NULL,
    description  TEXT DEFAULT '',
    cvss_score   REAL DEFAULT 0.0,
    poc_url      TEXT DEFAULT '',
    published_date TEXT DEFAULT '',
    fetched_at   TEXT NOT NULL
);
"""

# Tables that hold per-target scan data — wiped when target changes
_DATA_TABLES = ["findings", "endpoints", "hosts", "cve_cache"]


class StateDB:
    """
    Async context manager wrapping aiosqlite.

    Example:
        async with StateDB("mydb.db") as db:
            await db.insert_host(host)
    """

    def __init__(self, db_path: str = ".ghilliesuite_state.db", target: str | None = None) -> None:
        self._path = db_path
        self._target = target
        self._conn: aiosqlite.Connection | None = None

    # ── Context manager ───────────────────────────────────────────────────────

    async def __aenter__(self) -> "StateDB":
        self._conn = await aiosqlite.connect(self._path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(SCHEMA_SQL)
        await self._conn.commit()

        # ── Target-change detection ───────────────────────────────────────────
        # If the caller supplies a target and it differs from the stored one,
        # wipe all per-target data so old scan results never contaminate a new hunt.
        if self._target is not None:
            row = await (await self._conn.execute(
                "SELECT value FROM meta WHERE key = 'target'"
            )).fetchone()
            stored_target = row["value"] if row else None

            if stored_target != self._target:
                # Drop and recreate all data tables
                drop_sql = "\n".join(
                    f"DROP TABLE IF EXISTS {t};" for t in _DATA_TABLES
                )
                await self._conn.executescript(drop_sql)
                await self._conn.executescript(SCHEMA_SQL)
                # Persist the new target
                await self._conn.execute(
                    "INSERT OR REPLACE INTO meta (key, value) VALUES ('target', ?)",
                    (self._target,),
                )
                await self._conn.commit()

        return self

    async def __aexit__(self, *_) -> None:
        if self._conn:
            await self._conn.close()

    # ── Helpers ───────────────────────────────────────────────────────────────

    @property
    def _db(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("StateDB must be used as an async context manager.")
        return self._conn

    # ── Hosts ─────────────────────────────────────────────────────────────────

    async def insert_host(self, host: Host) -> int:
        """Insert or ignore a host record. Returns the row id."""
        cursor = await self._db.execute(
            """
            INSERT OR IGNORE INTO hosts (domain, ip, status_code, server, tech_stack, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (host.domain, host.ip, host.status_code, host.server, host.tech_stack, host.discovered_at),
        )
        await self._db.commit()
        # If ignored (duplicate), fetch the existing id
        if cursor.lastrowid == 0:
            row = await self._db.execute("SELECT id FROM hosts WHERE domain = ?", (host.domain,))
            result = await row.fetchone()
            return result["id"] if result else 0
        return cursor.lastrowid  # type: ignore[return-value]

    async def get_hosts(self, scope_domains: list[str] | None = None) -> list[Host]:
        """
        Return all live hosts, optionally filtered to in-scope domains.
        scope_domains may contain wildcards like '*.example.com'.
        """
        rows = await (await self._db.execute("SELECT * FROM hosts")).fetchall()
        hosts = [
            Host(
                id=r["id"],
                domain=r["domain"],
                ip=r["ip"],
                status_code=r["status_code"],
                server=r["server"],
                tech_stack=r["tech_stack"],
                discovered_at=r["discovered_at"],
            )
            for r in rows
        ]
        if scope_domains:
            hosts = [h for h in hosts if _is_in_scope(h.domain, scope_domains)]
        return hosts

    # ── Endpoints ─────────────────────────────────────────────────────────────

    async def insert_endpoint(self, ep: Endpoint) -> int:
        cursor = await self._db.execute(
            """
            INSERT OR IGNORE INTO endpoints (url, method, params, source_tool, host_id, found_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (ep.url, ep.method, ep.params, ep.source_tool, ep.host_id, ep.found_at),
        )
        await self._db.commit()
        return cursor.lastrowid or 0  # type: ignore[return-value]

    async def get_endpoints(
        self,
        host_id: int | None = None,
        with_params_only: bool = False,
    ) -> list[Endpoint]:
        """
        Fetch endpoints, optionally filtered by host or whether they have query params.
        with_params_only=True is used by ExploitAgent to find sqlmap/dalfox candidates.
        """
        query = "SELECT * FROM endpoints WHERE 1=1"
        params: list = []
        if host_id is not None:
            query += " AND host_id = ?"
            params.append(host_id)
        if with_params_only:
            query += " AND params != ''"
        rows = await (await self._db.execute(query, params)).fetchall()
        return [
            Endpoint(
                id=r["id"],
                url=r["url"],
                method=r["method"],
                params=r["params"],
                source_tool=r["source_tool"],
                host_id=r["host_id"],
                found_at=r["found_at"],
            )
            for r in rows
        ]

    # ── Findings ──────────────────────────────────────────────────────────────

    async def insert_finding(self, f: Finding) -> int:
        cursor = await self._db.execute(
            """
            INSERT INTO findings
              (tool, target, severity, title, evidence, reproducible_steps, raw_output, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f.tool, f.target, f.severity, f.title,
                f.evidence, f.reproducible_steps,
                f.raw_output[:2000],  # cap raw output to avoid DB bloat
                f.timestamp,
            ),
        )
        await self._db.commit()
        return cursor.lastrowid  # type: ignore[return-value]

    async def get_findings(self, severity: str | None = None) -> list[Finding]:
        query = "SELECT * FROM findings"
        params: list = []
        if severity:
            query += " WHERE severity = ?"
            params.append(severity.lower())
        query += " ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"
        rows = await (await self._db.execute(query, params)).fetchall()
        return [
            Finding(
                id=r["id"],
                tool=r["tool"],
                target=r["target"],
                severity=r["severity"],
                title=r["title"],
                evidence=r["evidence"],
                reproducible_steps=r["reproducible_steps"],
                raw_output=r["raw_output"],
                timestamp=r["timestamp"],
            )
            for r in rows
        ]

    # ── CVE Cache ─────────────────────────────────────────────────────────────

    async def get_cached_cve(self, keyword: str) -> CVEResult | None:
        row = await (
            await self._db.execute(
                "SELECT * FROM cve_cache WHERE keyword = ? ORDER BY fetched_at DESC LIMIT 1",
                (keyword.lower(),),
            )
        ).fetchone()
        if not row:
            return None
        return CVEResult(
            keyword=row["keyword"],
            cve_id=row["cve_id"],
            description=row["description"],
            cvss_score=row["cvss_score"],
            poc_url=row["poc_url"],
            published_date=row["published_date"],
            fetched_at=row["fetched_at"],
        )

    async def cache_cve(self, cve: CVEResult) -> None:
        await self._db.execute(
            """
            INSERT INTO cve_cache (keyword, cve_id, description, cvss_score, poc_url, published_date, fetched_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cve.keyword.lower(), cve.cve_id, cve.description,
                cve.cvss_score, cve.poc_url, cve.published_date, cve.fetched_at,
            ),
        )
        await self._db.commit()

    # ── Compact summary for AI ────────────────────────────────────────────────

    async def get_summary_for_ai(self) -> str:
        """
        Returns a compact JSON string (< ~500 tokens) that the AI uses to
        decide what to do next.  Raw tool output is NEVER passed to the LLM.
        """
        hosts = await self.get_hosts()
        endpoints = await self.get_endpoints()
        findings = await self.get_findings()

        summary = {
            "hosts_count": len(hosts),
            "hosts_sample": [
                {"domain": h.domain, "status": h.status_code, "tech": h.tech_stack}
                for h in hosts[:10]          # send max 10 examples
            ],
            "endpoints_count": len(endpoints),
            "endpoints_with_params": sum(1 for e in endpoints if e.params),
            "endpoints_sample": [e.url for e in endpoints[:10]],
            "findings": [
                {"severity": f.severity, "title": f.title, "target": f.target}
                for f in findings
            ],
        }
        return json.dumps(summary, indent=2)


# ── Scope helpers ─────────────────────────────────────────────────────────────

def _is_in_scope(domain: str, scope_domains: list[str]) -> bool:
    """Return True if domain matches any entry in scope_domains (wildcard aware)."""
    domain = domain.lower().strip()
    for sd in scope_domains:
        sd = sd.lower().strip().lstrip("*.")
        if domain == sd or domain.endswith("." + sd):
            return True
    return False
