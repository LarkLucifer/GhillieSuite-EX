"""
hcli/utils/parsers.py
─────────────────────
Structured output parsers for every tool in the arsenal.

CRITICAL DESIGN RULE:
  Raw tool output is NEVER sent to the LLM.
  Each parser distills stdout into a list of small, typed dicts that:
    1. Are written to the SQLite DB as Host/Endpoint/Finding records.
    2. Are summarised compactly by StateDB.get_summary_for_ai().

HOW TO ADD A PARSER FOR A NEW TOOL:
  1. Add a function named  parse_<tool_name>(output: str) -> list[dict]
  2. Add a corresponding ToolSpec.parser = "<tool_name>" in arsenal.py.
  3. The ExploitAgent/ReconAgent will automatically call it via get_parser().
"""

from __future__ import annotations

import json
import re
from typing import Any


# ── Helper ────────────────────────────────────────────────────────────────────

def get_parser(tool_name: str):
    """Return the parser function for a given tool name, or a passthrough."""
    parsers = {
        "subfinder": parse_subfinder,
        "httpx": parse_httpx,
        "katana": parse_katana,
        "gau": parse_gau,
        "nuclei": parse_nuclei,
        "dalfox": parse_dalfox,
        "sqlmap": parse_sqlmap,
        "trufflehog": parse_trufflehog,
    }
    return parsers.get(tool_name, _passthrough)


def _passthrough(output: str) -> list[dict[str, Any]]:
    """Default parser: split output into lines."""
    return [{"line": line} for line in output.splitlines() if line.strip()]


# ── Recon Parsers ─────────────────────────────────────────────────────────────

def parse_subfinder(output: str) -> list[dict[str, Any]]:
    """
    subfinder -silent produces one subdomain per line.
    Returns: [{"domain": str}, ...]
    """
    results = []
    for line in output.splitlines():
        line = line.strip()
        if line and "." in line:
            results.append({"domain": line.lower()})
    return results


def parse_httpx(output: str) -> list[dict[str, Any]]:
    """
    httpx with -silent -status-code -title -tech-detect outputs lines like:
      https://example.com [200] [Apache] [Title Here] [tech1,tech2]
    Also handles JSON output if -json flag is present.
    Returns: [{"url", "status_code", "server", "title", "tech_stack"}, ...]
    """
    results = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Try JSON first (httpx -json output)
        if line.startswith("{"):
            try:
                data = json.loads(line)
                results.append({
                    "url": data.get("url", ""),
                    "status_code": data.get("status-code", 0),
                    "server": data.get("webserver", ""),
                    "title": data.get("title", ""),
                    "tech_stack": ",".join(data.get("technologies", [])),
                })
                continue
            except json.JSONDecodeError:
                pass

        # Fallback: regex-based parsing of text output
        # Pattern: URL [STATUS] [TITLE] [TECH,TECH]
        url_match = re.match(r"(https?://\S+)", line)
        if not url_match:
            continue
        url = url_match.group(1)
        status_match = re.search(r"\[(\d{3})\]", line)
        status = int(status_match.group(1)) if status_match else 0
        brackets = re.findall(r"\[([^\]]+)\]", line)
        title = brackets[1] if len(brackets) > 1 else ""
        tech = brackets[2] if len(brackets) > 2 else ""

        results.append({
            "url": url,
            "status_code": status,
            "server": "",
            "title": title,
            "tech_stack": tech,
        })
    return results


def parse_katana(output: str) -> list[dict[str, Any]]:
    """
    katana -silent prints one URL per line.
    Extracts query parameters from URLs.
    Returns: [{"url": str, "params": str}, ...]
    """
    results = []
    for line in output.splitlines():
        line = line.strip()
        if not line or not line.startswith("http"):
            continue
        # Extract query parameter names
        param_match = re.search(r"\?([^#]+)", line)
        params = ""
        if param_match:
            params = ",".join(
                kv.split("=")[0]
                for kv in param_match.group(1).split("&")
                if kv
            )
        results.append({"url": line, "params": params})
    return results


def parse_gau(output: str) -> list[dict[str, Any]]:
    """
    gau prints one URL per line (may include many duplicates).
    Returns: [{"url": str, "params": str}, ...]
    """
    seen: set[str] = set()
    results = []
    for line in output.splitlines():
        line = line.strip()
        if not line or not line.startswith("http") or line in seen:
            continue
        seen.add(line)
        param_match = re.search(r"\?([^#]+)", line)
        params = ""
        if param_match:
            params = ",".join(
                kv.split("=")[0]
                for kv in param_match.group(1).split("&")
                if kv
            )
        results.append({"url": line, "params": params})
    return results


# ── Vuln Scan Parsers ─────────────────────────────────────────────────────────

def parse_nuclei(output: str) -> list[dict[str, Any]]:
    """
    nuclei -json outputs one JSON object per line.
    Each line: {"templateID", "type", "severity", "matched-at", "info": {...}}
    Returns: [{"severity", "template_id", "name", "matched_url", "description"}, ...]
    """
    results = []
    for line in output.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
            results.append({
                "severity": data.get("info", {}).get("severity", "info").lower(),
                "template_id": data.get("templateID", data.get("template-id", "")),
                "name": data.get("info", {}).get("name", ""),
                "matched_url": data.get("matched-at", ""),
                "description": data.get("info", {}).get("description", ""),
                "reference": ",".join(data.get("info", {}).get("reference", [])),
            })
        except json.JSONDecodeError:
            # nuclei sometimes prints non-JSON status lines; skip them
            pass
    return results


# ── Exploitation Parsers ──────────────────────────────────────────────────────

def parse_dalfox(output: str) -> list[dict[str, Any]]:
    """
    dalfox --format json outputs a JSON array or one JSON object per line.
    Returns: [{"type", "url", "payload", "evidence"}, ...]
    """
    results = []
    # Try to parse as a full JSON array first
    try:
        data = json.loads(output)
        if isinstance(data, list):
            for item in data:
                results.append({
                    "type": item.get("type", "XSS"),
                    "url": item.get("data", ""),
                    "payload": item.get("payload", ""),
                    "evidence": item.get("evidence", ""),
                })
            return results
    except (json.JSONDecodeError, TypeError):
        pass

    # Fallback: parse line by line
    for line in output.splitlines():
        line = line.strip()
        if "[V]" in line or "[POC]" in line:
            # dalfox text format: [V][A][ID] TYPE POC: <url>
            url_match = re.search(r"https?://\S+", line)
            results.append({
                "type": "XSS",
                "url": url_match.group(0) if url_match else "",
                "payload": "",
                "evidence": line[:300],
            })
    return results


def parse_sqlmap(output: str) -> list[dict[str, Any]]:
    """
    sqlmap --batch text output — detect injection points.
    Returns: [{"param", "technique", "dbms", "evidence"}, ...]
    """
    results = []
    current: dict[str, Any] = {}
    for line in output.splitlines():
        line = line.strip()
        if "is vulnerable" in line.lower() or "parameter" in line.lower() and "appears to be" in line.lower():
            # Extract parameter name
            param_match = re.search(r"(?:parameter|Parameter)['\s]+(['\w]+)['\s]+(?:appears|is)", line)
            if param_match:
                current["param"] = param_match.group(1)
        if "technique:" in line.lower():
            current["technique"] = line.split(":", 1)[-1].strip()
        if "back-end dbms:" in line.lower() or "web application technology:" in line.lower():
            current["dbms"] = line.split(":", 1)[-1].strip()
            current["evidence"] = line
        if current.get("param") and current.get("technique"):
            results.append({**current})
            current = {}

    # Last partial match
    if current.get("param"):
        results.append(current)

    return results


# ── Cloud / Secret Parsers ────────────────────────────────────────────────────

def parse_trufflehog(output: str) -> list[dict[str, Any]]:
    """
    trufflehog --json outputs one JSON object per line.
    Returns: [{"secret_type", "raw_value_redacted", "source", "url"}, ...]
    """
    results = []
    for line in output.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
            # Redact actual secret value for safe logging
            raw = data.get("Raw", data.get("raw", ""))
            redacted = raw[:4] + "…" + raw[-4:] if len(raw) > 8 else "[redacted]"
            results.append({
                "secret_type": data.get("DetectorName", data.get("detector_name", "Unknown")),
                "raw_value_redacted": redacted,
                "source": data.get("SourceMetadata", {}).get("Data", {}).get("Github", {}).get("repository", ""),
                "url": data.get("SourceMetadata", {}).get("Data", {}).get("Github", {}).get("link", ""),
            })
        except json.JSONDecodeError:
            pass
    return results
