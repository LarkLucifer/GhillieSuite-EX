"""
hcli/utils/cve_fetcher.py
─────────────────────────
Dynamic CVE / PoC fetcher callable by the AI agent.

Strategy:
  1. Check the local SQLite cache (via StateDB) to avoid hammering the API.
  2. Query NVD REST API v2 for recent CVEs matching the keyword.
  3. If NVD returns nothing, fall back to GitHub search for PoC repos.
  4. Return a structured CVEResult (stored in DB for future calls).

The AI calls this via AgentDecision(action="fetch_cve", cve_keyword="...").
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta

import httpx

from hcli.config import cfg
from hcli.state.models import CVEResult

# ── NVD API ───────────────────────────────────────────────────────────────────
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_SEARCH = "https://api.github.com/search/repositories"

# Cache expiry — re-fetch if older than this
CACHE_MAX_AGE_HOURS = 24


async def fetch_latest_cve(
    keyword: str,
    db=None,           # Optional StateDB instance for caching
) -> CVEResult:
    """
    Find the most relevant/recent CVE and PoC for a given technology keyword.

    Args:
        keyword: Technology or product name, e.g. "log4j", "apache struts 2.5"
        db:      Optional open StateDB for cache read/write.

    Returns:
        CVEResult dataclass. On failure, cve_id="ERROR" and description contains the message.
    """
    keyword = keyword.strip().lower()

    # ── 1. Check cache ─────────────────────────────────────────────────────
    if db is not None:
        cached = await db.get_cached_cve(keyword)
        if cached:
            age = datetime.utcnow() - datetime.fromisoformat(cached.fetched_at)
            if age < timedelta(hours=CACHE_MAX_AGE_HOURS):
                return cached

    # ── 2. Query NVD ───────────────────────────────────────────────────────
    result = await _fetch_from_nvd(keyword)

    # ── 3. GitHub fallback ─────────────────────────────────────────────────
    if result is None:
        result = await _fetch_from_github(keyword)

    # ── 4. Build error result if both failed ───────────────────────────────
    if result is None:
        result = CVEResult(
            keyword=keyword,
            cve_id="NOT_FOUND",
            description=f"No CVE or PoC found for '{keyword}'. Try a more specific keyword.",
        )

    # ── 5. Cache the result ────────────────────────────────────────────────
    if db is not None and result.cve_id not in ("NOT_FOUND", "ERROR"):
        try:
            await db.cache_cve(result)
        except Exception:
            pass  # Caching failure is non-fatal

    return result


async def _fetch_from_nvd(keyword: str) -> CVEResult | None:
    """Query NVD API v2 and return the most severe recent CVE."""
    params: dict = {
        "keywordSearch": keyword,
        "resultsPerPage": 5,
        "startIndex": 0,
    }
    headers: dict = {}
    if cfg.nvd_api_key:
        headers["apiKey"] = cfg.nvd_api_key

    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.get(NVD_BASE, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None

        # Sort by CVSS v3 score descending, pick highest
        best = None
        best_score = -1.0
        for item in vulnerabilities:
            cve = item.get("cve", {})
            metrics = cve.get("metrics", {})
            score = 0.0
            # Try CVSSv3.1 first, then v3.0, then v2
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(key, [])
                if metric_list:
                    score = metric_list[0].get("cvssData", {}).get("baseScore", 0.0)
                    break
            if score > best_score:
                best_score = score
                best = cve

        if not best:
            return None

        cve_id = best.get("id", "")
        descriptions = best.get("descriptions", [])
        desc = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No English description available.",
        )
        published = best.get("published", "")

        # Look for PoC reference link
        refs = best.get("references", [])
        poc_url = ""
        for ref in refs:
            url = ref.get("url", "")
            tags = [t.lower() for t in ref.get("tags", [])]
            if "exploit" in tags or "poc" in url.lower() or "github" in url.lower():
                poc_url = url
                break
        if not poc_url and refs:
            poc_url = refs[0].get("url", "")

        return CVEResult(
            keyword=keyword,
            cve_id=cve_id,
            description=desc[:500],
            cvss_score=best_score,
            poc_url=poc_url,
            published_date=published,
        )

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 403:
            # Rate-limited without API key; fall through to GitHub
            return None
        return CVEResult(
            keyword=keyword,
            cve_id="ERROR",
            description=f"NVD API error {e.response.status_code}: {e.response.text[:200]}",
        )
    except Exception as exc:
        return CVEResult(
            keyword=keyword,
            cve_id="ERROR",
            description=f"NVD request failed: {exc}",
        )


async def _fetch_from_github(keyword: str) -> CVEResult | None:
    """
    GitHub fallback — search for public PoC repositories for the keyword.
    Searches for repos matching '<keyword> CVE poc exploit'.
    """
    query = f"{keyword} CVE poc exploit"
    params = {
        "q": query,
        "sort": "stars",
        "order": "desc",
        "per_page": 3,
    }
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(GITHUB_SEARCH, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        items = data.get("items", [])
        if not items:
            return None

        top = items[0]
        # Try to extract a CVE ID from the repo name or description
        cve_match = __import__("re").search(
            r"CVE-\d{4}-\d+",
            (top.get("name", "") + " " + top.get("description", "")).upper(),
        )
        cve_id = cve_match.group(0) if cve_match else "GITHUB-POC"

        return CVEResult(
            keyword=keyword,
            cve_id=cve_id,
            description=(top.get("description") or f"GitHub PoC: {top['full_name']}")[:500],
            cvss_score=0.0,
            poc_url=top.get("html_url", ""),
            published_date=top.get("created_at", ""),
        )

    except Exception:
        return None
