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
        help="Directory where JSON + Markdown reports are saved.",
    ),
    max_loops: int = typer.Option(
        15,
        "--max-loops",
        help="Maximum number of agent decision loops.",
    ),
    timeout: int = typer.Option(
        180,
        "--timeout",
        help="Per-tool execution timeout in seconds.",
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
        max_loops=max_loops,
        timeout=timeout,
        safe_mode=safe_mode,
        update_templates=update_templates,
        cookie=cookie,
        header=header,
        force_auto=force_auto,
    )

    # Guard against "asyncio.run() cannot be called from a running event loop"
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import nest_asyncio
        nest_asyncio.apply()

    asyncio.run(coro)


async def _async_hunt(
    target: str,
    scope_input: str,
    output_dir: str,
    max_loops: int,
    timeout: int,
    safe_mode: bool,
    update_templates: bool,
    cookie: str | None,
    header: str | None,
    force_auto: bool = False,
) -> None:
    """Async implementation of the hunt command."""
    from ghilliesuite_ex.config import cfg, validate_config
    from ghilliesuite_ex.agents.supervisor import SupervisorAgent
    from ghilliesuite_ex.agents.base import AgentTask
    from ghilliesuite_ex.utils.executor import run_tool

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
    check_binaries(console)

    # ── Nuclei template update (non-blocking, runs in background) ─────────
    if update_templates:
        console.print("\n[cyan]Updating nuclei templates (nuclei -ut)…[/cyan]")
        nuclei_update = await run_tool(["nuclei", "-ut"], timeout=120)
        if nuclei_update.ok:
            console.print("[green]✔ Nuclei templates updated.[/green]")
        else:
            console.print(
                f"[yellow]⚠ nuclei -ut failed (continuing anyway): {nuclei_update.error[:80]}[/yellow]"
            )

    # ── Initialise AI client ───────────────────────────────────────────────
    ai_client = _build_ai_client(cfg)

    # ── Initialise DB and run supervisor ──────────────────────────────────
    console.print()
    console.print(Rule("[bold]Starting agent swarm[/bold]", style="bright_magenta"))

    cfg.max_agent_loops = max_loops
    cfg.default_timeout = timeout

    async with StateDB(cfg.db_path) as db:
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
        result = await supervisor.run(task)

        # ── Report Generation ─────────────────────────────────────────────
        console.print()
        console.print(Rule("[bold]Generating HTML Report[/bold]", style="bright_blue"))
        from ghilliesuite_ex.utils.reporter import HtmlReporter
        reporter = HtmlReporter(db=db, ai_client=ai_client, console=console, config=cfg)
        
        from rich.status import Status
        with Status("[blue]Consulting AI for plain-English summaries and rendering HTML report…[/blue]", console=console):
            report_path = await reporter.generate(
                target=target,
                scope=scope_domains,
                output_dir=output_dir,
            )

    console.print(f"\n[bold bright_green]Hunt complete! {result.summary}[/bold bright_green]")
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
