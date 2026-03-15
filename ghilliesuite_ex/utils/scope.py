"""
ghilliesuite_ex/utils/scope.py
───────────────────
Scope loading and enforcement.

This module is the guardian between the agent and out-of-scope assets.
Every tool execution path must go through these helpers to ensure that
no requests are sent to hosts outside the HackerOne program scope.

Usage:
    scope = load_scope("scope.txt")           # from file
    scope = load_scope("example.com,api.example.com")  # from CLI string
    filtered = enforce_scope(tool_output, scope)
"""

from __future__ import annotations

import re
from pathlib import Path


def load_scope(scope_input: str) -> list[str]:
    """
    Parse scope from either a comma-separated string or a file path.

    File format (scope.txt):
        # Comments are ignored
        example.com
        *.example.com
        api.example.com

    Args:
        scope_input: A comma-separated list of domains OR a path to a scope file.

    Returns:
        A deduplicated list of scope strings (wildcards preserved, e.g. '*.example.com').

    Raises:
        ValueError: If a file path is provided but does not exist.
    """
    path = Path(scope_input)
    if path.exists() and path.is_file():
        raw_lines = path.read_text(encoding="utf-8").splitlines()
    else:
        # Treat as comma-separated inline list
        raw_lines = [s.strip() for s in scope_input.split(",")]

    scope: list[str] = []
    for line in raw_lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Strip leading '*.' for normalised matching but keep original for display
        scope.append(line.lower())

    if not scope:
        raise ValueError(
            "Scope is empty! Provide at least one domain via --scope. "
            "Example: --scope example.com or --scope scope.txt"
        )

    return list(dict.fromkeys(scope))  # deduplicate, preserve order


def is_in_scope(host: str, scope_domains: list[str]) -> bool:
    """
    Return True if `host` matches any entry in `scope_domains`.
    Handles direct matches and wildcard entries (*.example.com).

    Args:
        host:         A domain, subdomain, or full URL.
        scope_domains: List from load_scope().
    """
    # Extract hostname from URLs
    url_match = re.search(r"https?://([^/:?#]+)", host)
    if url_match:
        host = url_match.group(1)

    host = host.lower().strip().rstrip(".")

    for sd in scope_domains:
        sd = sd.lower().strip()
        if sd.startswith("*."):
            base = sd[2:]  # strip '*.'
            if host == base or host.endswith("." + base):
                return True
        else:
            if host == sd or host.endswith("." + sd):
                return True

    return False


def enforce_scope(raw_output: str, scope_domains: list[str]) -> str:
    """
    Filter multi-line tool output to only lines that mention an in-scope host.
    Used for tools that don't natively support scope flags (e.g. gau, trufflehog).

    Args:
        raw_output:    Raw stdout from a tool.
        scope_domains: In-scope list from load_scope().

    Returns:
        Filtered string containing only in-scope lines.
    """
    lines = raw_output.splitlines()
    filtered = [line for line in lines if is_in_scope(line, scope_domains)]
    return "\n".join(filtered)


def scope_filter_domains(domains: list[str], scope_domains: list[str]) -> list[str]:
    """Filter a list of domain strings to in-scope entries only."""
    return [d for d in domains if is_in_scope(d, scope_domains)]


def scope_filter_urls(urls: list[str], scope_domains: list[str]) -> list[str]:
    """Filter a list of URLs to in-scope entries only."""
    return [u for u in urls if is_in_scope(u, scope_domains)]


def filter_in_scope(targets: list[str], scope_domains: list[str]) -> list[str]:
    """Return only targets that are in scope (domains or URLs)."""
    return [t for t in targets if is_in_scope(t, scope_domains)]
