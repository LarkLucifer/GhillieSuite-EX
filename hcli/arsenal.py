"""
hcli/arsenal.py
───────────────
Tool Registry — the single source of truth for every binary hcli.sec can invoke.

HOW TO EXTEND:
  1. Add an entry to TOOL_REGISTRY with the tool name as the key.
  2. Fill in a ToolSpec (see the dataclass below for all fields).
  3. Add a matching parser function in hcli/utils/parsers.py named parse_<tool_name>.
  4. Set hitl_required=True for ANY tool that sends active traffic or payloads.
  5. Done — the Supervisor AI will automatically discover and use the new tool via
     the description injected into its system prompt.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass

from rich.console import Console
from rich.table import Table


@dataclass
class ToolSpec:
    """Describes a single security tool available to the agent swarm."""

    binary: str
    """Executable name on PATH (e.g. 'subfinder', 'nuclei')."""

    base_cmd: list[str]
    """
    Command tokens. Placeholders:
        {target}  – the primary hunt target (domain/URL)
        {output}  – an output file path (if the tool needs -o)
    These are filled in by build_command() before execution.
    """

    scope_flag: str | None
    """
    How this tool accepts the in-scope domain, e.g. '-d {domain}'.
    Set to None if scope must be enforced via output filtering instead.
    """

    category: str
    """One of: Recon | VulnScan | Exploitation | Cloud"""

    parser: str
    """Name of the parser function in hcli/utils/parsers.py (parse_<parser>)."""

    hitl_required: bool
    """
    If True the ExploitAgent will call hitl_prompt() before executing this tool
    and will abort silently if the user answers 'n'.
    Set True for ANYTHING that sends active exploit payloads.
    """

    description: str
    """One-line description injected into the AI system prompt so the LLM
    knows when to suggest this tool."""


# ── Registry ──────────────────────────────────────────────────────────────────
TOOL_REGISTRY: dict[str, ToolSpec] = {

    # ── Recon & Discovery ─────────────────────────────────────────────────────

    "subfinder": ToolSpec(
        binary="subfinder",
        base_cmd=["subfinder", "-d", "{target}", "-silent", "-all"],
        scope_flag="-d {target}",
        category="Recon",
        parser="subfinder",
        hitl_required=False,
        description="Passive subdomain enumeration using many sources (certsh, virustotal, etc.).",
    ),

    "httpx": ToolSpec(
        binary="httpx",
        base_cmd=[
            "httpx", "-silent", "-status-code", "-title", "-tech-detect",
            "-follow-redirects", "-threads", "50",
        ],
        # httpx reads targets from stdin; scope enforced by feeding only in-scope hosts
        scope_flag=None,
        category="Recon",
        parser="httpx",
        hitl_required=False,
        description="HTTP probe — resolves hosts, detects status, server, tech stack, and page title.",
    ),

    "katana": ToolSpec(
        binary="katana",
        base_cmd=["katana", "-u", "{target}", "-silent", "-depth", "3", "-jc"],
        scope_flag="-u {target}",
        category="Recon",
        parser="katana",
        hitl_required=False,
        description="Fast web crawler — discovers endpoints, JS files, and form parameters.",
    ),

    "gau": ToolSpec(
        binary="gau",
        base_cmd=["gau", "{target}", "--threads", "5", "--subs"],
        scope_flag=None,  # gau takes domain as positional arg; enforced via scope filter
        category="Recon",
        parser="gau",
        hitl_required=False,
        description="Fetch known URLs from Wayback Machine, Common Crawl, and URLScan.",
    ),

    # ── Vulnerability Scanning ────────────────────────────────────────────────

    "nuclei": ToolSpec(
        binary="nuclei",
        base_cmd=[
            "nuclei", "-u", "{target}", "-silent",
            "-severity", "medium,high,critical",
            "-stats", "-json",
        ],
        scope_flag="-u {target}",
        category="VulnScan",
        parser="nuclei",
        hitl_required=False,  # HitL only for critical findings — handled in ExploitAgent
        description="Template-based vulnerability scanner; covers CVEs, misconfigs, exposures.",
    ),

    # ── Active Exploitation (HitL required) ───────────────────────────────────

    "dalfox": ToolSpec(
        binary="dalfox",
        base_cmd=["dalfox", "url", "{target}", "--silence", "--format", "json"],
        scope_flag="url {target}",
        category="Exploitation",
        parser="dalfox",
        hitl_required=True,
        description="XSS scanner and exploitation tool — discovers reflected, stored, and DOM XSS.",
    ),

    "sqlmap": ToolSpec(
        binary="sqlmap",
        base_cmd=[
            "sqlmap", "-u", "{target}",
            "--batch", "--level=2", "--risk=1",
            "--output-dir=.sqlmap_out", "--forms",
        ],
        scope_flag="-u {target}",
        category="Exploitation",
        parser="sqlmap",
        hitl_required=True,
        description="SQL injection detection and exploitation — tests GET/POST params and forms.",
    ),

    # ── Cloud / Secret Scanning ───────────────────────────────────────────────

    "trufflehog": ToolSpec(
        binary="trufflehog",
        base_cmd=["trufflehog", "github", "--org={target}", "--json"],
        scope_flag=None,
        category="Cloud",
        parser="trufflehog",
        hitl_required=False,
        description="Scans git repos for leaked secrets, credentials, and API keys.",
    ),
}


def build_command(
    tool_name: str,
    target: str,
    extra_args: list[str] | None = None,
) -> list[str]:
    """
    Resolve a ToolSpec's base_cmd by substituting the {target} placeholder.
    Optional extra_args are appended after the base command.

    Args:
        tool_name:  Key in TOOL_REGISTRY.
        target:     Domain, URL, or organisation name for the specific tool.
        extra_args: Additional CLI flags to append (e.g. ["-t", "10"]).

    Returns:
        A fully-formed list[str] ready for asyncio.create_subprocess_exec.
    """
    spec = TOOL_REGISTRY[tool_name]
    cmd = [tok.replace("{target}", target) for tok in spec.base_cmd]
    if extra_args:
        cmd.extend(extra_args)
    return cmd


def get_tool_descriptions(category_filter: str | None = None) -> str:
    """
    Return a formatted string listing tools and their descriptions.
    This is injected into the AI system prompt so the LLM knows what tools exist.

    Args:
        category_filter: If provided (e.g. 'Recon'), only list tools in that category.
    """
    lines: list[str] = []
    for name, spec in TOOL_REGISTRY.items():
        if category_filter and spec.category != category_filter:
            continue
        hitl = " ⚠️ [HitL required]" if spec.hitl_required else ""
        lines.append(f"  • {name} ({spec.category}){hitl}: {spec.description}")
    return "\n".join(lines)


def check_binaries(console: Console | None = None) -> dict[str, bool]:
    """
    Verify which tool binaries are present on PATH.
    Prints a Rich table if a console is provided.

    Returns:
        Mapping of tool_name → bool (True = found on PATH).
    """
    results: dict[str, bool] = {}
    for name, spec in TOOL_REGISTRY.items():
        results[name] = shutil.which(spec.binary) is not None

    if console:
        table = Table(title="Tool Arsenal — Binary Check", show_lines=True)
        table.add_column("Tool", style="bold cyan")
        table.add_column("Category", style="dim")
        table.add_column("Status")
        for name, found in results.items():
            status = "[green]✔ installed[/green]" if found else "[red]✘ missing[/red]"
            table.add_row(name, TOOL_REGISTRY[name].category, status)
        console.print(table)

    return results
