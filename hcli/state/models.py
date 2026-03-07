"""
hcli/state/models.py
────────────────────
Pure-Python dataclasses that represent structured data stored in the SQLite DB.
Using dataclasses (not an ORM) keeps dependencies minimal and the schema clear.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class Host:
    """A live host discovered during recon."""

    domain: str
    ip: str = ""
    status_code: int = 0
    server: str = ""
    tech_stack: str = ""          # comma-separated technologies detected by httpx
    discovered_at: str = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )
    id: int | None = None         # assigned by DB on insert


@dataclass
class Endpoint:
    """A URL or endpoint discovered by a crawler or URL-fetching tool."""

    url: str
    method: str = "GET"
    params: str = ""              # comma-separated query parameters
    source_tool: str = ""         # which tool found this (katana, gau, etc.)
    host_id: int | None = None    # FK → hosts.id
    found_at: str = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )
    id: int | None = None


@dataclass
class Finding:
    """A confirmed or suspected vulnerability."""

    tool: str
    target: str
    severity: str                 # critical | high | medium | low | info
    title: str
    evidence: str                 # brief human-readable evidence string
    reproducible_steps: str       # numbered steps for the report
    raw_output: str               # trimmed raw stdout excerpt (max 2000 chars)
    timestamp: str = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )
    id: int | None = None


@dataclass
class CVEResult:
    """A CVE entry fetched from NVD or GitHub."""

    keyword: str
    cve_id: str
    description: str
    cvss_score: float = 0.0
    poc_url: str = ""
    published_date: str = ""
    fetched_at: str = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )
