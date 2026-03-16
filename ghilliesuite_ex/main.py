"""
ghilliesuite_ex/main.py
─────────────────────
Typer CLI entrypoint for GhillieSuite-EX.sec.

Install:   pip install -e .
Run:       GhillieSuite-EX.sec hunt --target example.com --scope scope.txt

AI Provider is AUTO-DETECTED from .env — no --ai-provider flag needed:
  OPENAI_API_KEY=sk-...   → OpenAI (gpt-4o-mini)
  GEMINI_API_KEY=AIza...  → Google Gemini (gemini-2.5-pro)

Authentication flags (optional, injected into all active tools):
  --cookie "session=abc123"              → adds -H "Cookie: session=abc123"
  --header "Authorization: Bearer xyz"  → adds -H "Authorization: Bearer xyz"

Available commands:
  hunt          — Start a full AI-driven bug bounty hunt.
  check-tools   — Show which tool binaries are installed.
  check-config  — Validate .env / environment variables.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.rule import Rule

from ghilliesuite_ex import __app_name__, __version__
from ghilliesuite_ex.arsenal import check_binaries
from ghilliesuite_ex.config import validate_config
from ghilliesuite_ex.state.db import StateDB
from ghilliesuite_ex.utils.scope import load_scope
from ghilliesuite_ex.utils.ui import print_banner

app = typer.Typer(
    name=__app_name__,
    help="[bold cyan]GhillieSuite-EX.sec[/bold cyan] — AI Bug Bounty Orchestrator for HackerOne.",
    add_completion=False,
    rich_markup_mode="rich",
    no_args_is_help=True,
)

console = Console()


# ──────────────────────────────────────────────────────────────────────────────
# hunt
# ──────────────────────────────────────────────────────────────────────────────

@app.command()
def hunt(
    target: str = typer.Option(
        ...,
        "--target", "-t",
        help="Primary domain to hunt (e.g. example.com).",
        show_default=False,
    ),
    scope: str = typer.Option(
        ...,
        "--scope", "-s",
        help="In-scope domains — comma-separated string OR path to a scope file.",
        show_default=False,
    ),
    output: str = typer.Option(
        "reports",
        "--output", "-o",
        help="Directory where JSON + Markdown + HTML reports are saved.",
    ),
    evidence_dir: str = typer.Option(
        "evidence",
        "--evidence-dir",
        help="Directory where request/response evidence files are saved.",
    ),
    max_loops: int = typer.Option(
        5,
        "--max-loops",
        help="Maximum number of agent decision loops.",
    ),
    timeout: int = typer.Option(
        180,
        "--timeout",
        help="Per-tool execution timeout in seconds.",
    ),
    nuclei_timeout: Optional[int] = typer.Option(
        None,
        "--nuclei-timeout",
        help="Nuclei-only execution timeout in seconds.",
        show_default=False,
    ),
    fast_nuclei: Optional[bool] = typer.Option(
        None,
        "--fast-nuclei/--no-fast-nuclei",
        help="Enable aggressive Nuclei speed + severity filtering flags.",
        show_default=False,
    ),
    safe_mode: bool = typer.Option(
        False,
        "--safe-mode",
        help="Force Human-in-the-Loop for EVERY tool, not just exploitation ones.",
        is_flag=True,
    ),
    update_templates: bool = typer.Option(
        True,
        "--update-templates/--no-update-templates",
        help="Run 'nuclei -ut' on startup to fetch the latest CVE templates.",
    ),
    stealth: bool = typer.Option(
        False,
        "--stealth",
        help="Enable stealth rate-limiting to reduce WAF 429s (nuclei/sqlmap/ffuf).",
        is_flag=True,
    ),
    allow_redirects: bool = typer.Option(
        False,
        "--allow-redirects",
        help="Allow httpx to follow redirects during recon probing.",
        is_flag=True,
    ),
    disable_stealth: bool = typer.Option(
        False,
        "--disable-stealth",
        help="Disable sniper protocol and ignore WAF/Commander stealth signals (full-speed execution).",
        is_flag=True,
    ),
    cookie: Optional[str] = typer.Option(
        None,
        "--cookie", "-c",
        help=(
            "Session cookie string injected into all active tools as -H 'Cookie: ...'.\n"
            "Example: --cookie 'session=abc123; csrf_token=xyz'\n"
            "Enables authenticated scanning to discover post-login vulnerabilities."
        ),
        show_default=False,
    ),
    header: Optional[str] = typer.Option(
        None,
        "--header",
        help=(
            "Custom HTTP header injected into all active tools as -H '...'.\n"
            "Example: --header 'Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...'\n"
            "Can be combined with --cookie for full authenticated session support."
        ),
        show_default=False,
    ),
    screenshots: bool = typer.Option(
        False,
        "--screenshots",
        help="Enable gowitness screenshots during recon (optional).",
        is_flag=True,
    ),
    ai_planner: bool = typer.Option(
        False,
        "--ai-planner",
        help="Enable LLM advisory targeting in Supervisor (rules-first by default).",
        is_flag=True,
    ),
    force_auto: bool = typer.Option(
        False,
        "--force-auto",
        help=(
            "Bypass ALL Human-in-the-Loop prompts and run fully automatically. "
            "\n[bold red]WARNING:[/bold red] Only use on targets you are explicitly authorised to test. "
            "\nIdeal for CI/CD pipelines and scheduled automated scans."
        ),
        is_flag=True,
        rich_help_panel="Automation",
    ),
    force_exploit: bool = typer.Option(
        False,
        "--force-exploit",
        "--dumb-exploit",
        help=(
            "Brute-force mode for ExploitAgent. Bypasses AI Commander filtering and "
            "feeds all discovered parameterized URLs to dalfox/sqlmap and all hosts to nuclei."
        ),
        is_flag=True,
        rich_help_panel="Automation",
    ),
    js_workers: Optional[int] = typer.Option(
        None,
        "--js-workers",
        help="JS Deep Inspection: max concurrent JS downloads/workers.",
        show_default=False,
    ),
    js_max_files: Optional[int] = typer.Option(
        None,
        "--js-max-files",
        help="JS Deep Inspection: max JS files to analyze.",
        show_default=False,
    ),
    llm_concurrency: Optional[int] = typer.Option(
        None,
        "--llm-concurrency",
        help="JS Deep Inspection: max concurrent LLM verification calls.",
        show_default=False,
    ),
    js_snippet_len: Optional[int] = typer.Option(
        None,
        "--js-snippet-len",
        help="JS Deep Inspection: max snippet length sent to LLM.",
        show_default=False,
    ),
    js_http_timeout: Optional[float] = typer.Option(
        None,
        "--js-http-timeout",
        help="JS Deep Inspection: per-file download timeout (seconds).",
        show_default=False,
    ),
    js_llm_timeout: Optional[float] = typer.Option(
        None,
        "--js-llm-timeout",
        help="JS Deep Inspection: LLM verification timeout (seconds).",
        show_default=False,
    ),
) -> None:
    """
    Launch a full AI-driven bug bounty hunt against TARGET.

    AI provider is auto-detected from your .env:
      OPENAI_API_KEY=sk-...   → OpenAI (gpt-4o-mini)
      GEMINI_API_KEY=AIza...  → Google Gemini (gemini-2.5-pro)

    AUTHENTICATED SCANNING: Use --cookie and/or --header to inject session
    credentials into httpx, katana, nuclei, dalfox, and sqlmap. This enables
    discovery of post-authentication vulnerabilities commonly missed by
    unauthenticated scans.

    The Supervisor AI will orchestrate Recon, Exploit, and Reporter agents
    in an intelligent loop, storing all state in a local SQLite database.
    A JSON + Markdown report is saved to the OUTPUT directory on completion.
    """
    coro = _async_hunt(
        target=target,
        scope_input=scope,
        output_dir=output,
        evidence_dir=evidence_dir,
        max_loops=max_loops,
        timeout=timeout,
        nuclei_timeout=nuclei_timeout,
        fast_nuclei=fast_nuclei,
        safe_mode=safe_mode,
        update_templates=update_templates,
        stealth=stealth,
        allow_redirects=allow_redirects,
        disable_stealth=disable_stealth,
        cookie=cookie,
        header=header,
        screenshots=screenshots,
        ai_planner=ai_planner,
        force_auto=force_auto,
        force_exploit=force_exploit,
        js_workers=js_workers,
        js_max_files=js_max_files,
        llm_concurrency=llm_concurrency,
        js_snippet_len=js_snippet_len,
        js_http_timeout=js_http_timeout,
        js_llm_timeout=js_llm_timeout,
    )

    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(coro)
        else:
            loop.run_until_complete(coro)
    except RuntimeError:
        asyncio.run(coro)


async def _async_hunt(
    target: str,
    scope_input: str,
    output_dir: str,
    evidence_dir: str,
    max_loops: int,
    timeout: int,
    nuclei_timeout: int | None,
    fast_nuclei: bool | None,
    safe_mode: bool,
    update_templates: bool,
    stealth: bool,
    allow_redirects: bool,
    disable_stealth: bool,
    cookie: str | None,
    header: str | None,
    screenshots: bool = False,
    ai_planner: bool = False,
    force_auto: bool = False,
    force_exploit: bool = False,
    js_workers: int | None = None,
    js_max_files: int | None = None,
    llm_concurrency: int | None = None,
    js_snippet_len: int | None = None,
    js_http_timeout: float | None = None,
    js_llm_timeout: float | None = None,
) -> None:
    """Async implementation of the hunt command."""
    from ghilliesuite_ex.config import cfg, validate_config
    from ghilliesuite_ex.agents.supervisor import SupervisorAgent
    from ghilliesuite_ex.agents.base import AgentTask
    from ghilliesuite_ex.utils.nuclei import update_nuclei_templates

    # ── Banner ─────────────────────────────────────────────────────────────
    print_banner(console)

    # ── Auto-detect AI provider + validate ────────────────────────────────
    try:
        resolved_provider = validate_config()   # auto-detect; raises if none found
    except RuntimeError as exc:
        console.print(f"[bold red]Configuration error:[/bold red]\n{exc}")
        raise typer.Exit(code=1)

    _print_provider_log(resolved_provider)

    # ── Store auth credentials in global config ────────────────────────────
    # These are set here (not in Config.__init__) because they are per-session
    # CLI values, not environment variables.
    if cookie:
        cfg.auth_cookie = cookie.strip()
    if header:
        cfg.auth_header = header.strip()

    cfg.enable_screenshots = bool(screenshots)
    cfg.ai_planner = bool(ai_planner)
    cfg.force_exploit = bool(force_exploit)
    cfg.output_dir = output_dir
    cfg.evidence_dir = evidence_dir

    if force_exploit:
        console.print(
            "[bold red]FORCE-EXPLOIT MODE ACTIVE[/bold red]  "
            "[dim]- AI Commander filtering bypassed for ExploitAgent.[/dim]"
        )
        console.print("[dim]  dalfox/sqlmap: all URLs with params; nuclei: all hosts.[/dim]")
        console.print()

    if allow_redirects:
        cfg.allow_redirects = True
        console.print("[bold yellow]Redirects enabled[/bold yellow]  [dim]— httpx will follow redirects[/dim]")

    if stealth:
        cfg.stealth_mode = True
        console.print("[bold yellow]Stealth mode enabled[/bold yellow]  [dim]— lower request rate & concurrency[/dim]")

    if disable_stealth:
        cfg.disable_stealth = True
        if cfg.stealth_mode:
            console.print(
                "[bold yellow]Stealth override disabled[/bold yellow]  "
                "[dim]— --disable-stealth overrides --stealth[/dim]"
            )
        cfg.stealth_mode = False
        console.print(
            "[bold yellow]Sniper protocol disabled[/bold yellow]  "
            "[dim]— WAF signals will not reduce execution[/dim]"
        )

    if nuclei_timeout is not None:
        cfg.nuclei_timeout = nuclei_timeout

    if fast_nuclei is not None:
        cfg.fast_nuclei = bool(fast_nuclei)

    if js_workers is not None:
        cfg.js_max_workers = js_workers
    if js_max_files is not None:
        cfg.js_max_files = js_max_files
    if llm_concurrency is not None:
        cfg.js_llm_concurrency = llm_concurrency
    if js_snippet_len is not None:
        cfg.js_snippet_max_len = js_snippet_len
    if js_http_timeout is not None:
        cfg.js_http_timeout = js_http_timeout
    if js_llm_timeout is not None:
        cfg.js_llm_timeout = js_llm_timeout

    console.print(
        "[bold cyan]JS Deep Inspection config:[/bold cyan] "
        f"workers={cfg.js_max_workers}, "
        f"max_files={cfg.js_max_files}, "
        f"llm_concurrency={cfg.js_llm_concurrency}, "
        f"snippet_max_len={cfg.js_snippet_max_len}, "
        f"http_timeout={cfg.js_http_timeout}s, "
        f"llm_timeout={cfg.js_llm_timeout}s"
    )

    if cfg.is_authenticated:
        console.print(
            "[bold bright_yellow][+] Authenticated mode active[/bold bright_yellow]  "
            "[dim]— auth credentials will be injected into httpx, katana, nuclei, dalfox, sqlmap[/dim]"
        )
        if cfg.auth_cookie:
            preview = cfg.auth_cookie[:40] + "…" if len(cfg.auth_cookie) > 40 else cfg.auth_cookie
            console.print(f"    [dim]Cookie : {preview}[/dim]")
        if cfg.auth_header:
            preview = cfg.auth_header[:60] + "…" if len(cfg.auth_header) > 60 else cfg.auth_header
            console.print(f"    [dim]Header : {preview}[/dim]")
        console.print()

    # ── Force-auto mode ────────────────────────────────────────────────────
    if force_auto:
        cfg.force_auto = True
        console.print(
            "[bold red]⚠️  FORCE-AUTO MODE ACTIVE — All HitL prompts bypassed.[/bold red]\n"
            "[dim]   dalfox, sqlmap, and ffuf SSRF will fire without confirmation.\n"
            "   Only use on targets you are explicitly, legally authorised to test.[/dim]"
        )
        console.print()

    # ── Scope loading ──────────────────────────────────────────────────────
    try:
        scope_domains = load_scope(scope_input)
    except (ValueError, FileNotFoundError) as exc:
        console.print(f"[bold red]Scope error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    console.print(f"[green]✔[/green] Scope loaded: {', '.join(scope_domains)}")

    # Validate target is in scope
    from ghilliesuite_ex.utils.scope import is_in_scope
    if not is_in_scope(target, scope_domains):
        console.print(
            f"[bold red]❌ Target '{target}' is NOT in the provided scope![/bold red]\n"
            f"   Scope: {', '.join(scope_domains)}\n"
            f"   Add the target to your scope file or --scope string and retry."
        )
        raise typer.Exit(code=1)

    # ── Binary availability check ──────────────────────────────────────────
    console.print()
    results = check_binaries(console)
    missing = [name for name in ("subfinder", "katana") if not results.get(name)]
    if missing:
        console.print(
            f"\n[bold red]Missing required recon tools:[/bold red] {', '.join(missing)}\n"
            "Install them and ensure they are on your PATH, then re-run the hunt."
        )
        raise typer.Exit(code=1)

    # ── Nuclei template update (runs before hunting starts) ──────────────
    if update_templates:
        console.print("\n[cyan]Updating nuclei templates (nuclei -ut)…[/cyan]")
        nuclei_update = await asyncio.to_thread(update_nuclei_templates, 120)
        if nuclei_update.ok:
            console.print("[green]✔ Nuclei templates updated.[/green]")
        else:
            console.print(
                f"[yellow]⚠ nuclei -ut failed (continuing anyway): {nuclei_update.error[:80]}[/yellow]"
            )

    # ── Initialise AI client ───────────────────────────────────────────────
    ai_client = _build_ai_client(cfg)

    # ── Environment sanity checks ──────────────────────────────────────────
    import os
    import sqlite3

    db_file = cfg.db_path
    if os.path.exists(db_file):
        try:
            with sqlite3.connect(db_file) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT value FROM meta WHERE key = 'target'")
                row = cursor.fetchone()
                if row and row[0] != target:
                    console.print(f"[bold yellow]⚠ Stored target '{row[0]}' differs from current '{target}'. Shredding old DB to prevent data mixing.[/bold yellow]")
                    conn.close()
                    os.remove(db_file)
        except Exception:
            # If the database is malformed or locked, safest approach is deletion
            try:
                os.remove(db_file)
            except OSError:
                pass

    # ── Initialise DB and run supervisor ──────────────────────────────────
    console.print()
    console.print(Rule("[bold]Starting agent swarm[/bold]", style="bright_magenta"))

    cfg.max_agent_loops = max_loops
    cfg.default_timeout = timeout

    # Ensure the DB directory exists (for the hardcoded ~/GhillieSuite-EX/ path)
    import os as _os
    _db_dir = _os.path.dirname(_os.path.abspath(cfg.db_path))
    if _db_dir:
        _os.makedirs(_db_dir, exist_ok=True)

    result_summary = "Pipeline terminated early — see error log above."
    report_path    = None

    async with StateDB(cfg.db_path, target=target) as db:
        supervisor = SupervisorAgent(
            db=db,
            ai_client=ai_client,
            scope=scope_domains,
            console=console,
            config=cfg,
            safe_mode=safe_mode,
            max_loops=max_loops,
        )
        from ghilliesuite_ex.agents.base import AgentTask
        task = AgentTask(target=target, safe_mode=safe_mode)

        try:
            result = await supervisor.run(task)
            result_summary = result.summary
        except Exception as _agent_exc:
            console.print(
                f"\n[bold red]⚠ Agent swarm encountered an unhandled error:[/bold red]\n"
                f"  [red]{_agent_exc}[/red]\n"
                f"[dim]Continuing to report generation with findings collected so far.[/dim]"
            )

        # ── Report Generation (always runs, even if agent crashed) ────────
        console.print()
        console.print(Rule("[bold]Generating HTML Report[/bold]", style="bright_blue"))
        from ghilliesuite_ex.utils.reporter import HtmlReporter
        reporter = HtmlReporter(db=db, ai_client=ai_client, console=console, config=cfg)

        try:
            from rich.status import Status
            with Status("[blue]Consulting AI for plain-English summaries and rendering HTML report…[/blue]", console=console):
                report_path = await reporter.generate(
                    target=target,
                    scope=scope_domains,
                    output_dir=output_dir,
                )
        except Exception as _report_exc:
            console.print(f"[bold red]⚠ Report generation failed: {_report_exc}[/bold red]")

    console.print(f"\n[bold bright_green]Hunt complete! {result_summary}[/bold bright_green]")
    if report_path:
        console.print(f"Report saved at: [bold underline cyan]file://{report_path.resolve()}[/bold underline cyan]\n")



def _build_ai_client(config):
    """
    Construct the AI client using the auto-detected provider stored in cfg.
    Called once during hunt startup after validate_config() succeeds.
    """
    provider = config.ai_provider

    if provider == "openai":
        from openai import AsyncOpenAI
        return AsyncOpenAI(api_key=config.openai_api_key)

    if provider == "gemini":
        import google.generativeai as genai
        genai.configure(api_key=config.gemini_api_key)
        return genai.GenerativeModel(
            model_name=config.gemini_model,           # gemini-2.5-pro
            generation_config={"temperature": 0.2, "max_output_tokens": 1024},
        )

    # Should never reach here — validate_config() already caught this
    console.print(f"[bold red]No AI client could be built for provider '{provider}'.[/bold red]")
    raise typer.Exit(code=1)


def _print_provider_log(provider: str) -> None:
    """
    Print the styled '[+] Auto-detected AI Provider: ...' startup message.
    """
    from ghilliesuite_ex.config import cfg
    provider_styles = {
        "openai": ("bright_green", "🤖 OpenAI", cfg.openai_model),
        "gemini": ("bright_cyan",  "✨ Google Gemini", cfg.gemini_model),
    }
    color, label, model = provider_styles.get(
        provider, ("yellow", f"Unknown ({provider})", "?")
    )
    console.print(
        f"  [bold {color}][+] Auto-detected AI Provider: {label}[/bold {color}]  "
        f"[dim]model: {model}[/dim]"
    )
    console.print()


# ──────────────────────────────────────────────────────────────────────────────
# check-tools
# ──────────────────────────────────────────────────────────────────────────────

@app.command(name="check-tools")
def check_tools() -> None:
    """Show which security tool binaries are installed and available on PATH."""
    print_banner(console)
    results = check_binaries(console)
    missing = [name for name, found in results.items() if not found]
    if missing:
        console.print(
            f"\n[yellow]⚠  {len(missing)} tool(s) missing: {', '.join(missing)}[/yellow]"
        )
        console.print("[dim]Install missing tools and ensure they are on your PATH.[/dim]\n")
    else:
        console.print("\n[green]✔ All tools installed![/green]\n")


# ──────────────────────────────────────────────────────────────────────────────
# check-config
# ──────────────────────────────────────────────────────────────────────────────

@app.command(name="check-config")
def check_config() -> None:
    """Validate the .env configuration and show which AI provider was auto-detected."""
    print_banner(console)
    try:
        resolved = validate_config()   # auto-detect
        from ghilliesuite_ex.config import cfg
        _print_provider_log(resolved)
        console.print(f"[green]✔ Configuration valid.[/green]  Provider: [bold]{cfg.provider_display}[/bold]\n")
    except RuntimeError as exc:
        console.print(f"[bold red]Configuration error:[/bold red]\n{exc}\n")
        raise typer.Exit(code=1)


# ──────────────────────────────────────────────────────────────────────────────
# version
# ──────────────────────────────────────────────────────────────────────────────

@app.command()
def version() -> None:
    """Show the GhillieSuite-EX version."""
    console.print(f"[cyan]{__app_name__}[/cyan] v[bold]{__version__}[/bold]")


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()
