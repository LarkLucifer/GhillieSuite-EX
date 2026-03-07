"""
hcli/main.py
────────────
Typer CLI entrypoint for hcli.sec.

Install:   pip install -e .
Run:       hcli.sec hunt --target example.com --scope scope.txt

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

from hcli import __app_name__, __version__
from hcli.arsenal import check_binaries
from hcli.config import validate_config
from hcli.state.db import StateDB
from hcli.utils.scope import load_scope
from hcli.utils.ui import print_banner

app = typer.Typer(
    name=__app_name__,
    help="[bold cyan]hcli.sec[/bold cyan] — AI Bug Bounty Orchestrator for HackerOne.",
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
    ai_provider: str = typer.Option(
        "gemini",
        "--ai-provider",
        help="AI backend: 'gemini' or 'openai'.",
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
) -> None:
    """
    Launch a full AI-driven bug bounty hunt against TARGET.

    The Supervisor AI will orchestrate Recon, Exploit, and Reporter agents
    in an intelligent loop, storing all state in a local SQLite database.
    A JSON + Markdown report is saved to the OUTPUT directory on completion.
    """
    asyncio.run(
        _async_hunt(
            target=target,
            scope_input=scope,
            output_dir=output,
            max_loops=max_loops,
            timeout=timeout,
            ai_provider=ai_provider,
            safe_mode=safe_mode,
            update_templates=update_templates,
        )
    )


async def _async_hunt(
    target: str,
    scope_input: str,
    output_dir: str,
    max_loops: int,
    timeout: int,
    ai_provider: str,
    safe_mode: bool,
    update_templates: bool,
) -> None:
    """Async implementation of the hunt command."""
    from hcli.config import cfg
    from hcli.agents.supervisor import SupervisorAgent
    from hcli.agents.base import AgentTask
    from hcli.utils.executor import run_tool

    # ── Banner ─────────────────────────────────────────────────────────────
    print_banner(console)

    # ── Config validation ──────────────────────────────────────────────────
    try:
        validate_config(ai_provider)
    except RuntimeError as exc:
        console.print(f"[bold red]Configuration error:[/bold red]\n{exc}")
        raise typer.Exit(code=1)

    # ── Scope loading ──────────────────────────────────────────────────────
    try:
        scope_domains = load_scope(scope_input)
    except (ValueError, FileNotFoundError) as exc:
        console.print(f"[bold red]Scope error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    console.print(f"[green]✔[/green] Scope loaded: {', '.join(scope_domains)}")

    # Validate target is in scope
    from hcli.utils.scope import is_in_scope
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
    ai_client = _build_ai_client(ai_provider, cfg)

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
        from hcli.agents.base import AgentTask
        task = AgentTask(target=target, safe_mode=safe_mode)
        result = await supervisor.run(task)

    console.print(f"\n[bold bright_green]Hunt complete! {result.summary}[/bold bright_green]")
    console.print(f"Reports saved in: [underline]{Path(output_dir).resolve()}[/underline]\n")


def _build_ai_client(provider: str, config):
    """Construct the AI client object for the requested provider."""
    if provider == "gemini":
        import google.generativeai as genai
        genai.configure(api_key=config.gemini_api_key)
        return genai.GenerativeModel(
            model_name="gemini-1.5-flash",
            generation_config={"temperature": 0.2, "max_output_tokens": 1024},
        )

    if provider == "openai":
        from openai import AsyncOpenAI
        return AsyncOpenAI(api_key=config.openai_api_key)

    console.print(f"[bold red]Unknown AI provider: '{provider}'. Use 'gemini' or 'openai'.[/bold red]")
    raise typer.Exit(code=1)


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
def check_config(
    ai_provider: str = typer.Option("gemini", "--ai-provider"),
) -> None:
    """Validate the .env configuration and API keys."""
    print_banner(console)
    try:
        validate_config(ai_provider)
        console.print(f"[green]✔ Configuration valid for provider '{ai_provider}'.[/green]\n")
    except RuntimeError as exc:
        console.print(f"[bold red]Configuration error:[/bold red]\n{exc}\n")
        raise typer.Exit(code=1)


# ──────────────────────────────────────────────────────────────────────────────
# version
# ──────────────────────────────────────────────────────────────────────────────

@app.command()
def version() -> None:
    """Show the hcli.sec version."""
    console.print(f"[cyan]{__app_name__}[/cyan] v[bold]{__version__}[/bold]")


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()
