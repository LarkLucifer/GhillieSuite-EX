"""
ghilliesuite_ex/arsenal.py
───────────────
Tool Registry — the single source of truth for every binary GhillieSuite-EX can invoke.

HOW TO EXTEND:
  1. Add an entry to TOOL_REGISTRY with the tool name as the key.
  2. Fill in a ToolSpec (see the dataclass below for all fields).
  3. Add a matching parser function in ghilliesuite_ex/utils/parsers.py named parse_<tool_name>.
  4. Set hitl_required=True for ANY tool that sends active traffic or payloads.
  5. Done — the Supervisor AI will automatically discover and use the new tool via
     the description injected into its system prompt.

AUTH INJECTION:
  build_command() accepts optional auth_headers which are injected into tools
  that support the -H flag (httpx, katana, nuclei, dalfox, sqlmap).
  Pass as a flat list of header flag pairs: ["-H", "Cookie: ...", "-H", "Authorization: ..."]

FILE I/O:
  Tools marked with output_flag will write their results to disk instead of stdout.
  Use run_tool_to_file() from executor.py and pass the output path.
  Placeholder {output_file} is filled by build_command().
  Placeholder {input_file} is filled by build_command() for tools that read a list (httpx -l).
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console
from rich.table import Table


# ── Tools that accept auth headers via -H flag ────────────────────────────────
_AUTH_HEADER_TOOLS = frozenset({"httpx", "katana", "nuclei", "dalfox", "sqlmap"})

# ── Default short wordlist for ffuf (bundled fallback) ────────────────────────
# ── Default short wordlist for ffuf (bundled fallback) ────────────────────────
_BUNDLED_WORDLIST = str(
    Path(__file__).parent / "resources" / "common_dirs.txt"
)

# ── Tech-specific Smart Wordlists ─────────────────────────────────────────────
_PHP_WORDLIST = [
    ".env", ".env.example", ".env.backup", ".env.dev",
    "artisan", "telescope", "composer.json", "composer.lock",
    "config/database.php", "storage/logs/laravel.log"
]

_JAVA_SPRING_WORDLIST = [
    "actuator", "actuator/env", "actuator/heapdump", 
    "actuator/threaddump", "actuator/health", "jolokia",
    "WEB-INF/web.xml", "swagger-ui.html", "v2/api-docs"
]

_NODEJS_WORDLIST = [
    "package.json", "package-lock.json", "yarn.lock",
    "node_modules", ".npmrc", "tsconfig.json", "server.js",
    "app.js", ".env"
]

# ── Stealth Mode Overrides ────────────────────────────────────────────────────
# Applied when cfg.stealth_mode is True or build_command(..., stealth=True)
_STEALTH_ARGS: dict[str, list[str]] = {
    "nuclei": ["-rl", "15", "-c", "5", "-bs", "1", "-timeout", "5"],
    "sqlmap": ["--delay=1", "--random-agent"],
    "ffuf":   ["-t", "5", "-p", "0.5"],
    "dirb":   ["-t", "5", "-p", "0.5"],
}

# Extended stealth args applied when WAF evasion mode is enabled
_WAF_EVASION_STEALTH_ARGS: dict[str, list[str]] = {
    "sqlmap": ["--delay=2", "--random-agent", "--tamper=between,randomcase,space2comment"],
}

# SQLMap lethal extraction and WAF fallback arg sets
SQLMAP_LETHAL_ARGS = ["--dbs"]
SQLMAP_WAF_FALLBACK_ARGS = ["--tamper=space2comment,randomcase", "--random-agent"]


def apply_stealth_args(tool_name: str, cmd: list[str], enabled: bool) -> list[str]:
    """
    Inject conservative rate-limiting arguments for WAF avoidance.
    Removes existing conflicting flags before appending stealth args.
    """
    if not enabled or tool_name not in _STEALTH_ARGS:
        return list(cmd)

    cleaned: list[str] = []
    skip_next = False
    for tok in cmd:
        if skip_next:
            skip_next = False
            continue

        if tool_name in ("nuclei",):
            if tok in ("-rl", "-c", "-bs", "-timeout"):
                skip_next = True
                continue
        elif tool_name in ("ffuf", "dirb"):
            if tok in ("-t", "-p"):
                skip_next = True
                continue
        elif tool_name == "sqlmap":
            if tok == "--delay":
                skip_next = True
                continue
            if tok.startswith("--delay="):
                continue
        if tool_name in ("nuclei",) and tok.startswith(("-rl=", "-c=", "-bs=", "-timeout=")):
            continue

        cleaned.append(tok)

    stealth_args = _STEALTH_ARGS[tool_name]
    if tool_name == "nuclei":
        try:
            from ghilliesuite_ex.config import cfg as _cfg
            timeout = max(1, int(getattr(_cfg, "nuclei_http_timeout", 5)))
        except Exception:
            timeout = 5
        stealth_args = list(stealth_args)
        if "-timeout" in stealth_args:
            idx = stealth_args.index("-timeout")
            if idx + 1 < len(stealth_args):
                stealth_args[idx + 1] = str(timeout)

    cleaned.extend(stealth_args)
    return cleaned


def _apply_nuclei_tuning(
    cmd: list[str],
    rate_limit: int | None,
    concurrency: int | None,
    http_timeout: int | None,
) -> list[str]:
    """Override nuclei performance flags with configured values."""
    cleaned: list[str] = []
    skip_next = False
    for tok in cmd:
        if skip_next:
            skip_next = False
            continue
        if tok in ("-rl", "-c", "-timeout"):
            skip_next = True
            continue
        if tok.startswith(("-rl=", "-c=", "-timeout=")):
            continue
        cleaned.append(tok)

    if http_timeout is not None:
        cleaned.extend(["-timeout", str(max(1, int(http_timeout)))])
    if rate_limit is not None:
        cleaned.extend(["-rl", str(max(1, int(rate_limit)))])
    if concurrency is not None:
        cleaned.extend(["-c", str(max(1, int(concurrency)))])

    return cleaned


@dataclass
class ToolSpec:
    """Describes a single security tool available to the agent swarm."""

    binary: str
    """Executable name on PATH (e.g. 'subfinder', 'nuclei')."""

    base_cmd: list[str]
    """
    Command tokens. Placeholders:
        {target}      – the primary hunt target (domain/URL)
        {output_file} – an output file path that the tool writes to
        {input_file}  – an input file path the tool reads from (e.g. httpx -l)
        {wordlist}    – path to fuzzing wordlist (ffuf)
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
    """Name of the parser function in ghilliesuite_ex/utils/parsers.py (parse_<parser>)."""

    hitl_required: bool
    """
    If True the ExploitAgent will call hitl_prompt() before executing this tool
    and will abort silently if the user answers 'n'.
    Set True for ANYTHING that sends active exploit payloads.
    """

    description: str
    """One-line description injected into the AI system prompt so the LLM
    knows when to suggest this tool."""

    uses_output_file: bool = False
    """If True, build_command() expects callers to pass output_file kwarg."""

    uses_input_file: bool = False
    """If True, build_command() expects callers to pass input_file kwarg."""

    supports_auth_headers: bool = field(init=False)

    def __post_init__(self) -> None:
        self.supports_auth_headers = self.binary in _AUTH_HEADER_TOOLS


# ── Registry ──────────────────────────────────────────────────────────────────
TOOL_REGISTRY: dict[str, ToolSpec] = {

    # ── Recon & Discovery ─────────────────────────────────────────────────────

    "subfinder": ToolSpec(
        binary="subfinder",
        base_cmd=["subfinder", "-d", "{target}", "-silent", "-all", "-o", "{output_file}"],
        scope_flag="-d {target}",
        category="Recon",
        parser="subfinder",
        hitl_required=False,
        uses_output_file=True,
        description="Passive subdomain enumeration using many sources (certsh, virustotal, etc.). Writes results to a file.",
    ),

    "dnsx": ToolSpec(
        binary="dnsx",
        base_cmd=["dnsx", "-l", "{input_file}", "-json", "-o", "{output_file}"],
        scope_flag=None,
        category="Recon",
        parser="dnsx",
        hitl_required=False,
        uses_output_file=True,
        uses_input_file=True,
        description="DNS resolution for subdomains; returns domain->IP mappings.",
    ),

    "naabu": ToolSpec(
        binary="naabu",
        base_cmd=[
            "naabu", "-list", "{input_file}", "-json", "-o", "{output_file}",
            "-top-ports", "1000", "-silent",
        ],
        scope_flag=None,
        category="Recon",
        parser="naabu",
        hitl_required=False,
        uses_output_file=True,
        uses_input_file=True,
        description="Fast port discovery for discovered hosts; JSON output for parsing.",
    ),

    "httpx": ToolSpec(
        binary="httpx",
        base_cmd=[
            "httpx",
            "-l", "{input_file}",
            "-silent", "-status-code", "-title", "-tech-detect",
            "-random-agent",       # WAF bypass: rotate User-Agent per request
            "-retries", "2",       # retry failed probes instead of silently dropping
            "-rl", "50",           # rate-limit to 50 req/s — avoids 429/WAF blocks
            "-json", "-o", "{output_file}",
        ],
        # httpx reads from -l file; scope enforced by feeding only in-scope hosts
        scope_flag=None,
        category="Recon",
        parser="httpx",
        hitl_required=False,
        uses_output_file=True,
        uses_input_file=True,
        description="HTTP probe — resolves hosts, detects status, server, tech stack, and page title. WAF-resilient: random-agent + retries + rate limit. JSON file output.",
    ),

    "katana": ToolSpec(
        binary="katana",
        base_cmd=[
            "katana", "-u", "{target}",
            "-silent",
            "-d", "3",
            "-jc",
            "-ct", "5m",
            "-f", "qurl",
            "-ef",
            "js,css,png,jpg,jpeg,svg,woff,woff2,ico,webp,gif,map,mp4,pdf,"
            "bmp,tif,tiff,ttf,otf,eot,mp3,wav,ogg,webm,m4a,m4v,avi,mov,mkv,"
            "zip,rar,7z,tar,gz,tgz,bz2,iso,exe,dmg,apk",
        ],
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

    "arjun": ToolSpec(
        binary="arjun",
        base_cmd=["arjun", "-i", "{input_file}", "-oJ", "{output_file}", "-t", "10"],
        scope_flag=None,
        category="Recon",
        parser="arjun",
        hitl_required=False,
        uses_output_file=True,
        uses_input_file=True,
        description="Fast parameter discovery; uses 10 threads and JSON output.",
    ),

    "subzy": ToolSpec(
        binary="subzy",
        base_cmd=["subzy", "run", "--targets", "{input_file}", "--output", "{output_file}", "--json"],
        scope_flag=None,
        category="Recon",
        parser="subzy",
        hitl_required=False,
        uses_output_file=True,
        uses_input_file=True,
        description="Subdomain takeover detection using fingerprint checks.",
    ),

    "gowitness": ToolSpec(
        binary="gowitness",
        base_cmd=["gowitness", "file", "-f", "{input_file}", "--json", "-o", "{output_file}"],
        scope_flag=None,
        category="Recon",
        parser="gowitness",
        hitl_required=False,
        uses_output_file=True,
        uses_input_file=True,
        description="Captures screenshots of live web endpoints (optional).",
    ),

    # ── Vulnerability Scanning ────────────────────────────────────────────────

    "nuclei": ToolSpec(
        binary="nuclei",
        base_cmd=[
            "nuclei", "-u", "{target}",
            "-tags", "cve,ssrf,lfi,misconfig,exposure,graphql",  # targeted high-signal templates only
            "-severity", "medium,high,critical",
            "-timeout", "5",  # fail fast on tarpits
            "-rl", "150",     # rate-limit to 150 req/s ? avoids WAF/IDS triggers
            "-c", "50",       # concurrency: 50 parallel template checks
            "-silent", "-j",
        ],
        scope_flag="-u {target}",
        category="VulnScan",
        parser="nuclei",
        hitl_required=False,  # HitL only for critical findings — handled in ExploitAgent
        description="Template-based vulnerability scanner; targeted to CVE/SSRF/LFI/misconfig/graphql tags. Rate-limited for stealth.",
    ),

    # ── Active Exploitation (HitL required) ───────────────────────────────────

    "dalfox": ToolSpec(
        binary="dalfox",
        base_cmd=[
            "dalfox", "file", "{target}", 
            "--silence", "--format", "json", "-o", "{output_file}", "-w", "50",
            "--skip-bav", "--skip-mining-dom", "--skip-mining-dict"
        ],
        scope_flag=None,
        category="Exploitation",
        parser="dalfox",
        hitl_required=False,
        description="XSS scanner and exploitation tool — discovers reflected, stored, and DOM XSS (Bulk Mode).",
    ),

    "sqlmap": ToolSpec(
        binary="sqlmap",
        base_cmd=[
            "sqlmap", "-u", "{target}",
            "--batch", "--smart", "--threads=10",
            "--keep-alive", "--timeout=10", "--retries=1",
            "--output-dir=.sqlmap_out", "--forms",
        ],
        scope_flag="-u {target}",
        category="Exploitation",
        parser="sqlmap",
        hitl_required=False,
        description="SQL injection 'Speedrun' mode: fast, smart, and multi-threaded.",
    ),

    "ffuf": ToolSpec(
        binary="ffuf",
        base_cmd=[
            "ffuf",
            "-w", "{wordlist}",
            "-u", "{target}/FUZZ",
            "-of", "json", "-o", "{output_file}",
            "-mc", "200,204,301,302,307,401,403",
            "-t", "40",
            "-s",  # silent
        ],
        scope_flag=None,
        category="Exploitation",
        parser="ffuf",
        hitl_required=False,  # Directory brute-force is non-destructive; SSRF payloads use force_auto
        uses_output_file=True,
        description=(
            "(?url=, ?path=, ?redirect=). Active SSRF payloads still gated by force_auto."
        ),
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
    output_file: str | Path | None = None,
    input_file: str | Path | None = None,
    wordlist: str | None = None,
    auth_headers: list[str] | None = None,
    stealth: bool | None = None,
    allow_redirects: bool | None = None,
    tech_stack: str = "",
) -> list[str]:
    """
    Resolve a ToolSpec's base_cmd by substituting all placeholders.

    Placeholders resolved:
        {target}       → target string
        {output_file}  → str(output_file)  [required if spec.uses_output_file]
        {input_file}   → str(input_file)   [required if spec.uses_input_file]
        {wordlist}     → wordlist or default bundled wordlist (ffuf only)

    Auth injection:
        If auth_headers is provided and the tool supports -H flags,
        the header pairs are appended BEFORE extra_args so they appear
        close to the base invocation.  Example:
            auth_headers=["-H", "Cookie: session=abc", "-H", "Authorization: Bearer xyz"]

    Args:
        tool_name:    Key in TOOL_REGISTRY.
        target:       Domain, URL, or organisation name.
        extra_args:   Additional CLI flags to append.
        output_file:  Path where the tool should write its output (for file-I/O tools).
        input_file:   Path the tool should read its input from (e.g. httpx -l).
        wordlist:     Path to wordlist (ffuf). Falls back to bundled list.
        auth_headers: Flat list of header flag pairs, e.g. ["-H", "Cookie: ..."].
        stealth:      If True, apply conservative rate-limiting overrides.

    Returns:
        A fully-formed list[str] ready for asyncio.create_subprocess_exec.
    """
    spec = TOOL_REGISTRY[tool_name]
    if spec.uses_output_file and output_file is None:
        raise ValueError(f"{tool_name} requires output_file but none was provided")
    if spec.uses_input_file and input_file is None:
        raise ValueError(f"{tool_name} requires input_file but none was provided")
    out_str = str(output_file) if output_file else ""
    in_str  = str(input_file)  if input_file  else ""
    
    # Context-Aware Smart Wordlist Selection
    wl_str = wordlist
    if not wl_str:
        tech = tech_stack.lower()
        if any(kw in tech for kw in ("php", "laravel", "symfony")):
            wl_str = _write_temp_wordlist("php", _PHP_WORDLIST)
        elif any(kw in tech for kw in ("java", "spring", "tomcat", "jboss")):
            wl_str = _write_temp_wordlist("java", _JAVA_SPRING_WORDLIST)
        elif any(kw in tech for kw in ("node", "express", "next.js")):
            wl_str = _write_temp_wordlist("node", _NODEJS_WORDLIST)
        else:
            wl_str = _BUNDLED_WORDLIST

    cmd = []
    for tok in spec.base_cmd:
        tok = tok.replace("{target}",      target)
        tok = tok.replace("{output_file}", out_str)
        tok = tok.replace("{input_file}",  in_str)
        tok = tok.replace("{wordlist}",    wl_str)
        cmd.append(tok)

    # Inject auth headers for supported tools
    if auth_headers and spec.supports_auth_headers:
        cmd.extend(auth_headers)

    if extra_args:
        cmd.extend(extra_args)

    if tool_name == "nuclei":
        try:
            from ghilliesuite_ex.config import cfg as _cfg
            cmd = _apply_nuclei_tuning(
                cmd,
                getattr(_cfg, "nuclei_rate_limit", None),
                getattr(_cfg, "nuclei_concurrency", None),
                getattr(_cfg, "nuclei_http_timeout", None),
            )
        except Exception:
            pass

    if allow_redirects is None:
        try:
            from ghilliesuite_ex.config import cfg as _cfg
            allow_redirects = bool(getattr(_cfg, "allow_redirects", False))
        except Exception:
            allow_redirects = False

    if allow_redirects and tool_name == "httpx" and "-follow-redirects" not in cmd:
        cmd.append("-follow-redirects")

    if stealth is None:
        try:
            from ghilliesuite_ex.config import cfg as _cfg
            stealth = bool(getattr(_cfg, "stealth_mode", False))
        except Exception:
            stealth = False

    if stealth:
        cmd = apply_stealth_args(tool_name, cmd, enabled=True)

    return cmd


def _write_temp_wordlist(name: str, payload_list: list[str]) -> str:
    """Helper to write a dynamic wordlist to tmp/ and return its path."""
    tmp_dir = Path("tmp")
    tmp_dir.mkdir(parents=True, exist_ok=True)
    out_path = tmp_dir / f"wordlist_{name}.txt"
    if not out_path.exists():
        out_path.write_text("\n".join(payload_list), encoding="utf-8")
    return str(out_path)


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
