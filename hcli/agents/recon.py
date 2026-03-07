"""
hcli/agents/recon.py
────────────────────
ReconAgent — passive and active reconnaissance with DAG concurrency.

This agent runs multiple non-intrusive recon tools CONCURRENTLY using
asyncio.gather (forming a simple DAG):

  Phase 1 (concurrent DAG):   subfinder + gau     ← both run at the same time
  Phase 2 (sequential):       httpx               ← probes discovered subdomains
  Phase 3 (sequential):       katana              ← crawls live HTTP services

All results are written to the SQLite DB via StateDB.
Raw stdout is never passed to the LLM; parsers convert it to structured dicts.
"""

from __future__ import annotations

import asyncio

from rich.spinner import Spinner
from rich.status import Status

from hcli.arsenal import TOOL_REGISTRY, build_command
from hcli.state.models import Endpoint, Host
from hcli.utils.executor import run_tool
from hcli.utils.parsers import get_parser
from hcli.utils.scope import is_in_scope, scope_filter_domains, scope_filter_urls
from hcli.utils.ui import tool_result_panel

from .base import AgentResult, AgentTask, BaseAgent


class ReconAgent(BaseAgent):
    """
    Runs subfinder, gau, httpx, and katana in an optimised dag order.
    All tools have hitl_required=False so no user confirmation is needed.
    """

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        timeout = self.cfg.default_timeout
        items_added = 0

        # ── Phase 1: Concurrent subdomain + URL discovery ──────────────────
        self.console.print(f"[cyan]  Phase 1 — Concurrent: subfinder + gau → {target}[/cyan]")

        with Status("[cyan]Running subfinder + gau concurrently…[/cyan]", console=self.console):
            sf_result, gau_result = await asyncio.gather(
                run_tool(build_command("subfinder", target), timeout=timeout),
                run_tool(build_command("gau", target), timeout=timeout),
                return_exceptions=False,
            )

        # ── Parse subfinder ────────────────────────────────────────────────
        subdomains: list[str] = []
        if sf_result.ok:
            parsed = get_parser("subfinder")(sf_result.stdout)
            raw_domains = [r["domain"] for r in parsed]
            subdomains = scope_filter_domains(raw_domains, self.scope)
            for domain in subdomains:
                await self.db.insert_host(Host(domain=domain))
                items_added += 1
        else:
            self.console.print(f"[dim]subfinder: {sf_result.error or sf_result.stderr[:100]}[/dim]")

        tool_result_panel(
            self.console, "subfinder",
            build_command("subfinder", target),
            sf_result.ok,
            f"Found {len(subdomains)} in-scope subdomain(s)",
        )

        # ── Parse gau ─────────────────────────────────────────────────────
        gau_urls: list[str] = []
        if gau_result.ok:
            parsed = get_parser("gau")(gau_result.stdout)
            raw_urls = [r["url"] for r in parsed]
            gau_urls = scope_filter_urls(raw_urls, self.scope)
            for entry in get_parser("gau")(gau_result.stdout):
                if is_in_scope(entry["url"], self.scope):
                    ep = Endpoint(
                        url=entry["url"],
                        params=entry.get("params", ""),
                        source_tool="gau",
                    )
                    await self.db.insert_endpoint(ep)
                    items_added += 1
        else:
            self.console.print(f"[dim]gau: {gau_result.error or gau_result.stderr[:100]}[/dim]")

        tool_result_panel(
            self.console, "gau",
            build_command("gau", target),
            gau_result.ok,
            f"Found {len(gau_urls)} in-scope URL(s)",
        )

        # ── Phase 2: httpx probe all live subdomains ───────────────────────
        all_hosts = subdomains if subdomains else [target]
        stdin_data = "\n".join(all_hosts)
        self.console.print(f"[cyan]  Phase 2 — httpx probing {len(all_hosts)} host(s)…[/cyan]")

        httpx_cmd = TOOL_REGISTRY["httpx"].base_cmd[:]
        with Status("[cyan]httpx probing…[/cyan]", console=self.console):
            httpx_result = await run_tool(
                httpx_cmd,
                timeout=timeout,
                stdin_data=stdin_data,
            )

        live_count = 0
        if httpx_result.ok:
            parsed_hosts = get_parser("httpx")(httpx_result.stdout)
            for item in parsed_hosts:
                if not item.get("url") or not is_in_scope(item["url"], self.scope):
                    continue
                host = Host(
                    domain=item["url"].split("//")[-1].split("/")[0],
                    status_code=item.get("status_code", 0),
                    server=item.get("server", ""),
                    tech_stack=item.get("tech_stack", ""),
                )
                host_id = await self.db.insert_host(host)
                items_added += 1
                live_count += 1

                # Add the root URL as an endpoint too
                if host_id:
                    ep = Endpoint(url=item["url"], source_tool="httpx", host_id=host_id)
                    await self.db.insert_endpoint(ep)

        tool_result_panel(
            self.console, "httpx", httpx_cmd, httpx_result.ok,
            f"Found {live_count} live HTTP service(s)",
        )

        # ── Phase 3: Katana crawl of live hosts ────────────────────────────
        live_hosts = await self.db.get_hosts(self.scope)
        katana_urls_found = 0

        # Only crawl the top 5 hosts to avoid very long runs
        for host in live_hosts[:5]:
            url_target = f"https://{host.domain}"
            self.console.print(f"[cyan]  Phase 3 — katana crawling {url_target}[/cyan]")

            # Use task.tool_name override if supervisor specified one
            if task.tool_name and task.tool_name != "katana":
                self.console.print(f"[dim]  Supervisor specified {task.tool_name} — skipping katana.[/dim]")
                break

            with Status(f"[cyan]Crawling {url_target}…[/cyan]", console=self.console):
                katana_result = await run_tool(
                    build_command("katana", url_target),
                    timeout=timeout,
                )

            if katana_result.ok:
                parsed_eps = get_parser("katana")(katana_result.stdout)
                for item in parsed_eps:
                    if is_in_scope(item["url"], self.scope):
                        ep = Endpoint(
                            url=item["url"],
                            params=item.get("params", ""),
                            source_tool="katana",
                            host_id=host.id,
                        )
                        await self.db.insert_endpoint(ep)
                        items_added += 1
                        katana_urls_found += 1
            else:
                self.console.print(f"[dim]katana: {katana_result.error[:80]}[/dim]")

        tool_result_panel(
            self.console, "katana",
            build_command("katana", f"https://{live_hosts[0].domain}" if live_hosts else target),
            True,
            f"Crawled {katana_urls_found} endpoint(s)",
        )

        return AgentResult(
            agent=self.name,
            status="ok",
            summary=(
                f"Recon complete — {len(subdomains)} subdomains, "
                f"{live_count} live hosts, "
                f"{katana_urls_found} crawled endpoints."
            ),
            items_added=items_added,
        )
