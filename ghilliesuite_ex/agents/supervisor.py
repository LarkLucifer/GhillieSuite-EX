"""
ghilliesuite_ex/agents/supervisor.py
─────────────────────────
SupervisorAgent — the orchestration brain of GhillieSuite-EX.

Responsibilities:
  1. Read a compact DB summary (never raw tool output).
  2. Ask the AI: "What should the next agent + tool be?"
  3. Dispatch to ReconAgent, ExploitAgent, or ReporterAgent.
  4. Iterate up to MAX_AGENT_LOOPS; stop when AI returns phase="done".

The Supervisor never touches files or runs tools directly.
All state changes happen inside the specialised agents.
"""

from __future__ import annotations

import json
import re

from rich.console import Console
from rich.rule import Rule

from ghilliesuite_ex.config import Config, cfg
from ghilliesuite_ex.state.db import StateDB
from ghilliesuite_ex.utils.ui import agent_panel, status_dashboard

from .base import AgentResult, AgentTask, BaseAgent
from .exploit import ExploitAgent
from .recon import ReconAgent
from .reporter import ReporterAgent

# ── System prompt injected into every Supervisor AI call ──────────────────────
SUPERVISOR_SYSTEM_PROMPT = """\
You are an automated Bug Bounty Hunter operating on an AUTHORISED HackerOne target.
Your job is to orchestrate a team of specialised agents to find vulnerabilities.

Available agents:
  • recon    — Runs passive/active reconnaissance (subfinder, httpx, katana, gau).
               Use this first and any time you want more data about the target.
  • exploit  — Runs vulnerability scanners and exploitation tools (nuclei, dalfox, sqlmap).
               Only use after recon has found live hosts and endpoints.
  • reporter — Compiles all findings from the database into a final report.
               Use this when no more useful discoveries are expected.

Focus on: IDOR, SSRF, XSS, SQL Injection, Open Redirect, and latest CVEs.

You will receive a JSON snapshot of the current database state.
Based on that, respond with ONLY a JSON object (no markdown fences, no prose):
{
  "phase": "recon" | "exploit" | "reporter" | "fetch_cve" | "done",
  "agent": "ReconAgent" | "ExploitAgent" | "ReporterAgent",
  "tool": "<tool_name from registry, or null>",
  "target": "<specific domain or URL to test>",
  "reason": "<one sentence explaining your decision>",
  "cve_keyword": "<keyword if phase=fetch_cve, else null>"
}

Rules:
  - NEVER suggest a tool that is not in the registry.
  - NEVER suggest targeting an out-of-scope domain.
  - If hosts_count == 0, always start with recon.
  - If findings already cover the majority of endpoints, move to reporter.
  - Prefer high-impact vulnerabilities (critical/high severity).
  - When in doubt, do more recon.
"""


class SupervisorAgent(BaseAgent):
    """
    Hierarchical supervisor that delegates tasks to specialised sub-agents
    and drives the main hunt loop.
    """

    def __init__(
        self,
        db: StateDB,
        ai_client,
        scope: list[str],
        console: Console,
        config: Config | None = None,
        safe_mode: bool = False,
        max_loops: int | None = None,
    ) -> None:
        super().__init__(db, ai_client, scope, console, config)
        self.safe_mode = safe_mode
        self.max_loops = max_loops or self.cfg.max_agent_loops

        # Instantiate sub-agents (all share the same DB + AI client)
        self.recon_agent = ReconAgent(db, ai_client, scope, console, config)
        self.exploit_agent = ExploitAgent(db, ai_client, scope, console, config)
        self.reporter_agent = ReporterAgent(db, ai_client, scope, console, config)

    async def run(self, task: AgentTask) -> AgentResult:
        """Drive the full hunt loop for task.target."""
        target = task.target
        self.console.print(
            Rule(f"[bold bright_magenta]🕵  Hunt started — target: {target}[/bold bright_magenta]",
                 style="bright_magenta")
        )

        total_findings = 0

        for loop in range(1, self.max_loops + 1):
            # ── Get compact DB summary for AI ──────────────────────────────
            db_summary = await self.db.get_summary_for_ai()

            # ── Ask Supervisor AI what to do next ──────────────────────────
            decision = await self._decide(db_summary, target)

            if decision is None:
                self.console.print("[yellow]⚠  AI returned an unparseable decision. Stopping.[/yellow]")
                break

            phase = decision.get("phase", "done")
            agent_name = decision.get("agent", "ReporterAgent")
            tool = decision.get("tool")
            sub_target = decision.get("target", target)
            reason = decision.get("reason", "")
            cve_keyword = decision.get("cve_keyword")

            # ── Display current agent action ────────────────────────────────
            agent_panel(self.console, agent_name, tool or phase, sub_target, loop, self.max_loops)

            # ── Handle fetch_cve phase ──────────────────────────────────────
            if phase == "fetch_cve" and cve_keyword:
                await self._handle_fetch_cve(cve_keyword)
                continue

            # ── Terminal condition ──────────────────────────────────────────
            if phase == "done":
                self.console.print("[bright_green]✔  AI has decided the hunt is complete.[/bright_green]")
                break

            # ── Dispatch to sub-agent ───────────────────────────────────────
            sub_task = AgentTask(
                target=sub_target,
                tool_name=tool,
                reason=reason,
                safe_mode=self.safe_mode,
            )

            result = await self._dispatch(phase, sub_task)
            total_findings += result.items_added if result.status == "ok" else 0

            self.console.print(
                f"[dim]  → {result.agent}: {result.summary}[/dim]"
            )

            # ── Live dashboard after each agent turn ────────────────────────
            hosts = await self.db.get_hosts()
            endpoints = await self.db.get_endpoints()
            findings = await self.db.get_findings()
            eps_with_params = sum(1 for e in endpoints if e.params)

            status_dashboard(
                self.console,
                hosts=len(hosts),
                endpoints=len(endpoints),
                findings=len(findings),
                endpoints_with_params=eps_with_params,
            )

        # ── Always run reporter at the end ──────────────────────────────────
        self.console.print(Rule("[bold bright_green]📋  Compiling Report[/bold bright_green]", style="bright_green"))
        await self.reporter_agent.run(AgentTask(target=target))

        return AgentResult(
            agent=self.name,
            status="ok",
            summary=f"Hunt complete. {total_findings} finding(s) stored.",
            items_added=total_findings,
        )

    # ── Internal helpers ───────────────────────────────────────────────────────

    async def _decide(self, db_summary: str, target: str) -> dict | None:
        """
        Ask the AI for the next action. Returns a parsed dict or None on failure.
        The prompt deliberately sends ONLY the compact DB summary (tokens-safe).
        """
        prompt = (
            f"Target: {target}\n"
            f"In-scope domains: {', '.join(self.scope)}\n\n"
            f"Current state:\n{db_summary}"
        )
        raw = await self._ask_ai(prompt, system=SUPERVISOR_SYSTEM_PROMPT)

        if not raw:
            return None

        # Extract JSON even if the AI wrapped it in markdown fences
        json_match = re.search(r"\{.*\}", raw, re.DOTALL)
        if not json_match:
            self.console.print(f"[dim red]AI response was not JSON:\n{raw[:300]}[/dim red]")
            return None

        try:
            return json.loads(json_match.group(0))
        except json.JSONDecodeError as exc:
            self.console.print(f"[dim red]JSON parse error: {exc}[/dim red]")
            return None

    async def _dispatch(self, phase: str, task: AgentTask) -> AgentResult:
        """Route a phase string to the correct sub-agent."""
        route: dict[str, BaseAgent] = {
            "recon": self.recon_agent,
            "exploit": self.exploit_agent,
            "reporter": self.reporter_agent,
        }
        agent = route.get(phase, self.reporter_agent)
        try:
            return await agent.run(task)
        except Exception as exc:
            return AgentResult(
                agent=agent.name,
                status="error",
                summary=f"Unhandled exception in {agent.name}",
                error=str(exc),
            )

    async def _handle_fetch_cve(self, keyword: str) -> None:
        """Fetch a CVE and cache the result in the DB."""
        from ghilliesuite_ex.utils.cve_fetcher import fetch_latest_cve
        self.console.print(f"[cyan]🔍  Fetching CVE for: {keyword}[/cyan]")
        result = await fetch_latest_cve(keyword, db=self.db)
        self.console.print(
            f"  [bold]{result.cve_id}[/bold]  CVSS {result.cvss_score}  "
            f"{result.description[:120]}…"
        )
        if result.poc_url:
            self.console.print(f"  [dim]PoC: {result.poc_url}[/dim]")
