"""
ghilliesuite_ex/utils/parsers.py
─────────────────────
Structured output parsers for every tool in the arsenal.

CRITICAL DESIGN RULE:
  Raw tool output is NEVER sent to the LLM.
  Each parser distills stdout into a list of small, typed dicts that:
    1. Are written to the SQLite DB as Host/Endpoint/Finding records.
    2. Are summarised compactly by StateDB.get_summary_for_ai().

FILE I/O PARSERS:
  parse_subfinder() and parse_httpx() can accept a Path to an output file
  written by the tool (via -o or -json -o flags). This is the preferred mode
  for reliable output capture. Pass output_path=Path("...") to activate.
  Falling back to a raw string is still supported for backwards compatibility.

URL FILTERING (parse_katana, parse_gau):
  Static assets (images, fonts, CSS, sourcemaps, etc.) are silently dropped.
  Only URLs that contain parameters (?key=val) or match high-value API/auth
  path patterns are stored. This reduces DB noise and LLM token waste.

HOW TO ADD A PARSER FOR A NEW TOOL:
  1. Add a function named  parse_<tool_name>(output: str, **kwargs) -> list[dict]
  2. Add a corresponding ToolSpec.parser = "<tool_name>" in arsenal.py.
  3. The ExploitAgent/ReconAgent will automatically call it via get_parser().
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


# ── Static asset denylist — URLs matching these extensions are dropped ─────────
STATIC_EXT_DENYLIST: frozenset[str] = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".ico", ".svg", ".avif",
    ".mp4", ".mp3", ".mov", ".avi", ".webm",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".css",
    ".map",   # JS sourcemaps — no logic
    ".pdf", ".zip", ".tar", ".gz", ".rar",
})

# Path fragments that always indicate a high-value endpoint regardless of params
_HIGH_VALUE_PATH_FRAGMENTS: tuple[str, ...] = (
    "/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/gql",
    "/rest/", "/admin", "/dashboard", "/login", "/logout",
    "/auth", "/oauth", "/signin", "/signup", "/register",
    "/user", "/account", "/profile", "/me/",
    "/order", "/payment", "/checkout",
    "/upload", "/import", "/export", "/download",
    "/config", "/settings", "/debug",
    "/webhook", "/callback", "/redirect",
)

# Keywords in page title or tech stack that suggest an AI/LLM surface
_AI_TECH_KEYWORDS: tuple[str, ...] = (
    "chatgpt", "openai", "gemini", "claude", "copilot",
    "llm", "chatbot", "assistant", "gpt",
    "langchain", "llama", "mistral", "huggingface",
    "ai chat", "ai assistant",
)


def is_high_value_url(url: str) -> bool:
    """
    Return True if this URL is worth storing and testing.

    Rules (any one match is sufficient):
      1. Has a query string with at least one parameter.
      2. Path contains a high-value API/auth/admin fragment.

    Static asset extensions are NEVER high-value regardless of other rules
    — the caller is responsible for pre-filtering with has_static_extension().
    """
    url_lower = url.lower()
    # Rule 1: has parameters
    if "?" in url:
        return True
    # Rule 2: high-value path
    for fragment in _HIGH_VALUE_PATH_FRAGMENTS:
        if fragment in url_lower:
            return True
    return False


def has_static_extension(url: str) -> bool:
    """Return True if the URL path ends with a known static asset extension."""
    try:
        # Strip query string and fragment before checking suffix
        path = url.split("?")[0].split("#")[0].lower()
        suffix = Path(path).suffix
        return suffix in STATIC_EXT_DENYLIST
    except Exception:
        return False


def detect_ai_tech(title: str = "", tech_stack: str = "", server: str = "") -> bool:
    """
    Return True if the combined page metadata suggests an AI/LLM-backed service.
    Used by parse_httpx() to set the ai_detected flag on host records.
    """
    combined = f"{title} {tech_stack} {server}".lower()
    return any(kw in combined for kw in _AI_TECH_KEYWORDS)


# ── Helper ────────────────────────────────────────────────────────────────────

def get_parser(tool_name: str):
    """Return the parser function for a given tool name, or a passthrough."""
    parsers = {
        "subfinder":  parse_subfinder,
        "httpx":      parse_httpx,
        "katana":     parse_katana,
        "gau":        parse_gau,
        "nuclei":     parse_nuclei,
        "dalfox":     parse_dalfox,
        "sqlmap":     parse_sqlmap,
        "trufflehog": parse_trufflehog,
        "ffuf":       parse_ffuf,
    }
    return parsers.get(tool_name, _passthrough)


def _passthrough(output: str, **kwargs) -> list[dict[str, Any]]:
    """Default parser: split output into lines."""
    return [{"line": line} for line in output.splitlines() if line.strip()]


# ── Recon Parsers ─────────────────────────────────────────────────────────────

def parse_subfinder(output: str = "", output_path: Path | None = None) -> list[dict[str, Any]]:
    """
    Parse subfinder output.  Preferred mode: read from -o output file.
    Fallback: parse raw stdout string.

    subfinder -silent -o produces one subdomain per line.
    Returns: [{"domain": str}, ...]
    """
    if output_path and output_path.exists():
        try:
            text = output_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = output
    else:
        text = output

    results = []
    for line in text.splitlines():
        line = line.strip()
        if line and "." in line:
            results.append({"domain": line.lower()})
    return results


def parse_httpx(output: str = "", output_path: Path | None = None) -> list[dict[str, Any]]:
    """
    Parse httpx JSON output.  Preferred mode: read from -json -o output file.

    Each JSON object contains:
      url, status-code, webserver, title, technologies, host
    Also detects AI/LLM-backed services and sets ai_detected=True.

    Returns: [{"url", "status_code", "server", "title", "tech_stack", "ai_detected"}, ...]
    """
    if output_path and output_path.exists():
        try:
            text = output_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = output
    else:
        text = output

    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue

        # ── JSON mode (httpx -json) ────────────────────────────────────────
        if line.startswith("{"):
            try:
                data = json.loads(line)
                title     = data.get("title", "")
                tech_list = data.get("technologies", [])
                tech_str  = ",".join(tech_list)
                server    = data.get("webserver", "")
                results.append({
                    "url":          data.get("url", ""),
                    "status_code":  data.get("status-code", 0),
                    "server":       server,
                    "title":        title,
                    "tech_stack":   tech_str,
                    "ai_detected":  detect_ai_tech(title, tech_str, server),
                })
                continue
            except json.JSONDecodeError:
                pass

        # ── Fallback: text output (httpx -silent -status-code -title) ─────
        url_match = re.match(r"(https?://\S+)", line)
        if not url_match:
            continue
        url = url_match.group(1)
        status_match = re.search(r"\[(\d{3})\]", line)
        status = int(status_match.group(1)) if status_match else 0
        brackets = re.findall(r"\[([^\]]+)\]", line)
        title = brackets[1] if len(brackets) > 1 else ""
        tech  = brackets[2] if len(brackets) > 2 else ""

        results.append({
            "url":         url,
            "status_code": status,
            "server":      "",
            "title":       title,
            "tech_stack":  tech,
            "ai_detected": detect_ai_tech(title, tech),
        })
    return results


def parse_katana(output: str, **kwargs) -> list[dict[str, Any]]:
    """
    Parse katana crawl output (one URL per line).

    Smart filtering applied:
      - Static asset extensions are dropped entirely.
      - Only high-value URLs (with params or API paths) are returned.

    Returns: [{"url": str, "params": str}, ...]
    """
    seen: set[str] = set()
    results = []
    for line in output.splitlines():
        line = line.strip()
        if not line or not line.startswith("http") or line in seen:
            continue
        seen.add(line)

        # Filter out static assets
        if has_static_extension(line):
            continue

        # Only keep high-value URLs
        if not is_high_value_url(line):
            continue

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


def parse_gau(output: str, **kwargs) -> list[dict[str, Any]]:
    """
    Parse gau URL output (one URL per line, many duplicates).

    Smart filtering applied (same rules as parse_katana):
      - Static asset extensions are dropped.
      - Only parameterised or high-value API/auth URLs are returned.

    Returns: [{"url": str, "params": str}, ...]
    """
    seen: set[str] = set()
    results = []
    for line in output.splitlines():
        line = line.strip()
        if not line or not line.startswith("http") or line in seen:
            continue
        seen.add(line)

        # Filter out static assets
        if has_static_extension(line):
            continue

        # Only keep high-value URLs
        if not is_high_value_url(line):
            continue

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

def parse_nuclei(output: str, **kwargs) -> list[dict[str, Any]]:
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
                "severity":    data.get("info", {}).get("severity", "info").lower(),
                "template_id": data.get("templateID", data.get("template-id", "")),
                "name":        data.get("info", {}).get("name", ""),
                "matched_url": data.get("matched-at", ""),
                "description": data.get("info", {}).get("description", ""),
                "reference":   ",".join(data.get("info", {}).get("reference", [])),
            })
        except json.JSONDecodeError:
            # nuclei sometimes prints non-JSON status lines; skip them
            pass
    return results


# ── Exploitation Parsers ──────────────────────────────────────────────────────

def parse_dalfox(output: str, **kwargs) -> list[dict[str, Any]]:
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
                url_val = item.get("data", "").strip()
                if not url_val:
                    continue  # Skip empty or malformed payload records
                results.append({
                    "type":     item.get("type", "XSS"),
                    "url":      url_val,
                    "payload":  item.get("payload", ""),
                    "evidence": item.get("evidence", ""),
                })
            return results
    except (json.JSONDecodeError, TypeError):
        pass

    # Fallback: parse line by line
    for line in output.splitlines():
        line = line.strip()
        if "[V]" in line or "[POC]" in line:
            url_match = re.search(r"https?://\S+", line)
            results.append({
                "type":     "XSS",
                "url":      url_match.group(0) if url_match else "",
                "payload":  "",
                "evidence": line[:300],
            })
    return results


def parse_sqlmap(output: str, **kwargs) -> list[dict[str, Any]]:
    """
    sqlmap --batch text output — detect injection points.
    Returns: [{"param", "technique", "dbms", "evidence"}, ...]
    """
    results = []
    current: dict[str, Any] = {}
    for line in output.splitlines():
        line = line.strip()
        if "is vulnerable" in line.lower() or "parameter" in line.lower() and "appears to be" in line.lower():
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

    if current.get("param"):
        results.append(current)

    return results


def parse_ffuf(output: str = "", output_path: Path | None = None, **kwargs) -> list[dict[str, Any]]:
    """
    Parse ffuf JSON output.  Preferred mode: read from -of json -o output file.

    ffuf JSON schema (top-level "results" array):
      {"results": [{"url", "status", "length", "lines", "words", "input": {...}}, ...]}

    Returns: [{"url": str, "status": int, "length": int, "lines": int}, ...]
    """
    if output_path and output_path.exists():
        try:
            text = output_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = output
    else:
        text = output

    if not text.strip():
        return []

    try:
        data = json.loads(text)
        raw_results = data.get("results", [])
        return [
            {
                "url":    item.get("url", ""),
                "status": item.get("status", 0),
                "length": item.get("length", 0),
                "lines":  item.get("lines", 0),
            }
            for item in raw_results
            if item.get("url")
        ]
    except (json.JSONDecodeError, TypeError, AttributeError):
        pass

    # Fallback: ffuf sometimes writes one JSON object per line
    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
            if item.get("url"):
                results.append({
                    "url":    item.get("url", ""),
                    "status": item.get("status", 0),
                    "length": item.get("length", 0),
                    "lines":  item.get("lines", 0),
                })
        except json.JSONDecodeError:
            pass
    return results


# ── Cloud / Secret Parsers ────────────────────────────────────────────────────

def parse_trufflehog(output: str, **kwargs) -> list[dict[str, Any]]:
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
            raw = data.get("Raw", data.get("raw", ""))
            redacted = raw[:4] + "…" + raw[-4:] if len(raw) > 8 else "[redacted]"
            results.append({
                "secret_type":        data.get("DetectorName", data.get("detector_name", "Unknown")),
                "raw_value_redacted": redacted,
                "source":             data.get("SourceMetadata", {}).get("Data", {}).get("Github", {}).get("repository", ""),
                "url":                data.get("SourceMetadata", {}).get("Data", {}).get("Github", {}).get("link", ""),
            })
        except json.JSONDecodeError:
            pass
    return results
