"""
ghilliesuite_ex/agents/recon.py
────────────────────
ReconAgent — passive and active reconnaissance with DAG concurrency.

Pipeline (DAG order):
  Phase 1 (concurrent):  subfinder → writes tmp/subfinder_out.txt
                         gau       → stdout (high-value URLs only)
  Phase 2 (sequential):  httpx     → reads tmp/subfinder_out.txt, writes tmp/httpx_out.json
  Phase 3 (sequential):  katana    → crawls each live host (high-value URLs only)

KEY CHANGES vs v1:
  • File I/O replaces stdin piping for subfinder→httpx handoff.
    subfinder uses -o flag; httpx uses -l + -json -o flags.
    This eliminates the stdout-buffering bug that caused httpx to miss live hosts.

  • Auth credentials from cfg.auth_headers_flags are injected into httpx and
    katana commands so authenticated endpoints are probed correctly.

  • AI/LLM tech detection: if parse_httpx() returns ai_detected=True for a host,
    the DB Host record is tagged with ai_detected=True. ExploitAgent reads this
    flag to generate Prompt Injection advisories.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from rich.status import Status

from ghilliesuite_ex.arsenal import TOOL_REGISTRY, build_command
from ghilliesuite_ex.config import cfg as global_cfg
from ghilliesuite_ex.state.models import Endpoint, Host
from ghilliesuite_ex.utils.executor import run_tool, run_tool_to_file
from ghilliesuite_ex.utils.parsers import get_parser, parse_subfinder, parse_httpx
from ghilliesuite_ex.utils.scope import is_in_scope, scope_filter_domains, scope_filter_urls
from ghilliesuite_ex.utils.ui import tool_result_panel

from .base import AgentResult, AgentTask, BaseAgent

# ── Temp file locations for inter-tool data handoff ───────────────────────────
_TMP_DIR          = Path("tmp")
_SUBFINDER_OUT    = _TMP_DIR / "subfinder_out.txt"
_HTTPX_OUT        = _TMP_DIR / "httpx_out.json"


class ReconAgent(BaseAgent):
    """
    Runs subfinder, gau, httpx, and katana in an optimised DAG order.
    All tools have hitl_required=False so no user confirmation is needed.
    Auth credentials from cfg are injected into httpx and katana.
    """

    async def run(self, task: AgentTask) -> AgentResult:
        target  = task.target
        timeout = self.cfg.default_timeout
        items_added = 0

        # Resolve auth headers once — shared by httpx and katana
        auth_headers = self.cfg.auth_headers_flags  # [] if no auth configured

        # ── Phase 1: Concurrent subfinder + gau (with Redundancy Check) ───
        self.console.print(f"[cyan]  Phase 1 — Concurrent: subfinder + gau → {target}[/cyan]")

        root_domain = target.split("//")[-1].split("/")[0].split(":")[0]
        sf_history: set[str] = getattr(self.cfg, "_subfinder_history", set())
        run_sf = root_domain not in sf_history

        sf_cmd = build_command(
            "subfinder", target,
            output_file=_SUBFINDER_OUT,
        )
        gau_cmd = build_command("gau", target)

        with Status("[cyan]Running subfinder + gau concurrently…[/cyan]", console=self.console):
            tasks = [run_tool(gau_cmd, timeout=timeout)]
            if run_sf:
                tasks.insert(0, run_tool_to_file(sf_cmd, _SUBFINDER_OUT, timeout=timeout))
                sf_history.add(root_domain)
                setattr(self.cfg, "_subfinder_history", sf_history)

            results = await asyncio.gather(*tasks, return_exceptions=False)
            
            if run_sf:
                sf_result = results[0]
                gau_result = results[1]
            else:
                sf_result = None
                gau_result = results[0]

        # ── Parse subfinder (read from output file) ────────────────────────
        subdomains: list[str] = []
        if sf_result and (sf_result.ok or sf_result.output_file):
            parsed = parse_subfinder(output_path=sf_result.output_file or _SUBFINDER_OUT)
            raw_domains = [r["domain"] for r in parsed]
            subdomains = scope_filter_domains(raw_domains, self.scope)
            for domain in subdomains:
                await self.db.insert_host(Host(domain=domain))
                items_added += 1
        elif sf_result:
            self.console.print(f"[dim]subfinder: {sf_result.error or sf_result.stderr[:100]}[/dim]")
        else:
            self.console.print(f"[dim]subfinder: skipped (root domain {root_domain} already scanned)[/dim]")

        if sf_result:
            tool_result_panel(
                self.console, "subfinder",
                sf_cmd, sf_result.ok or bool(sf_result.output_file),
                f"Found {len(subdomains)} in-scope subdomain(s)",
            )

        # ── Parse gau (smart-filtered high-value URLs only) ────────────────
        if gau_result.ok:
            parsed_gau = get_parser("gau")(gau_result.stdout)
            gau_urls_added = 0
            for entry in parsed_gau:
                if is_in_scope(entry["url"], self.scope):
                    ep = Endpoint(
                        url=entry["url"],
                        params=entry.get("params", ""),
                        source_tool="gau",
                    )
                    await self.db.insert_endpoint(ep)
                    items_added += 1
                    gau_urls_added += 1
        else:
            gau_urls_added = 0
            self.console.print(f"[dim]gau: {gau_result.error or gau_result.stderr[:100]}[/dim]")

        tool_result_panel(
            self.console, "gau",
            gau_cmd, gau_result.ok,
            f"Stored {gau_urls_added} high-value in-scope URL(s)",
        )

        # ── Phase 2: httpx — reads from subfinder output file ─────────────
        # If subfinder found nothing, fall back to probing the root target
        if not subdomains:
            self.console.print(
                "[yellow]  ⚠ subfinder found no subdomains — writing root target to input file[/yellow]"
            )
            _TMP_DIR.mkdir(parents=True, exist_ok=True)
            _SUBFINDER_OUT.write_text(target + "\n", encoding="utf-8")

        self.console.print(
            f"[cyan]  Phase 2 — httpx probing {len(subdomains) or 1} host(s) "
            f"from {_SUBFINDER_OUT}…[/cyan]"
        )

        httpx_cmd = build_command(
            "httpx", target,
            input_file=_SUBFINDER_OUT,
            output_file=_HTTPX_OUT,
            auth_headers=auth_headers,
        )

        with Status("[cyan]httpx probing…[/cyan]", console=self.console):
            httpx_result = await run_tool_to_file(httpx_cmd, _HTTPX_OUT, timeout=timeout)

        live_count = 0
        if httpx_result.ok or httpx_result.output_file:
            parsed_hosts = parse_httpx(output_path=httpx_result.output_file or _HTTPX_OUT)
            for item in parsed_hosts:
                if not item.get("url") or not is_in_scope(item["url"], self.scope):
                    continue
                host = Host(
                    domain=item["url"].split("//")[-1].split("/")[0],
                    status_code=item.get("status_code", 0),
                    server=item.get("server", ""),
                    tech_stack=item.get("tech_stack", ""),
                )
                # Tag AI/LLM hosts for Prompt Injection advisory in ExploitAgent
                host_id = await self.db.insert_host(host)
                items_added += 1
                live_count += 1

                # Flag AI-detected hosts in DB
                if item.get("ai_detected") and host_id:
                    try:
                        await self.db.tag_host(host_id, "ai_detected")
                    except Exception:
                        pass  # tag_host may not exist in older DB schema; non-fatal

                if host_id:
                    ep = Endpoint(url=item["url"], source_tool="httpx", host_id=host_id)
                    await self.db.insert_endpoint(ep)

        # ── Fallback for 0-Hosts (WAF Block Mitigation) ───────────────────
        if live_count == 0 and subdomains:
            self.console.print("[yellow]  ⚠ httpx returned 0 live hosts. WAF block suspected. Safely falling back to subfinder domains...[/yellow]")
            for domain in subdomains:
                await self.db._db.execute("UPDATE hosts SET status_code = 200, tech_stack = 'WAF-Fallback' WHERE domain = ?", (domain,))
                await self.db._db.commit()
                row = await (await self.db._db.execute("SELECT id FROM hosts WHERE domain = ?", (domain,))).fetchone()
                if row:
                    ep = Endpoint(url=f"https://{domain}", source_tool="fallback", host_id=row["id"])
                    await self.db.insert_endpoint(ep)
                live_count += 1

        tool_result_panel(
            self.console, "httpx", httpx_cmd,
            httpx_result.ok or bool(httpx_result.output_file),
            f"Found {live_count} live HTTP service(s)",
        )

        # ── Phase 3: Katana crawl of live hosts ────────────────────────────
        live_hosts = await self.db.get_hosts(self.scope)
        katana_urls_found = 0

        for host in live_hosts[:5]:   # cap at 5 to avoid very long runs
            url_target = f"https://{host.domain}"
            self.console.print(f"[cyan]  Phase 3 — katana crawling {url_target}[/cyan]")

            if task.tool_name and task.tool_name != "katana":
                self.console.print(f"[dim]  Supervisor specified {task.tool_name} — skipping katana.[/dim]")
                break

            katana_cmd = build_command(
                "katana", url_target,
                auth_headers=auth_headers,
            )

            with Status(f"[cyan]Crawling {url_target}…[/cyan]", console=self.console):
                katana_result = await run_tool(katana_cmd, timeout=timeout)

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
            f"Crawled {katana_urls_found} high-value endpoint(s)",
        )

        return AgentResult(
            agent=self.name,
            status="ok",
            summary=(
                f"Recon complete — {len(subdomains)} subdomains, "
                f"{live_count} live hosts, "
                f"{katana_urls_found} crawled endpoints. "
                f"(Auth: {'✔ active' if auth_headers else 'none'})"
            ),
            items_added=items_added,
        )
