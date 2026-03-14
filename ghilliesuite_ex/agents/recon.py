"""
ghilliesuite_ex/agents/recon.py
--------------------------------
ReconAgent - coverage-first reconnaissance.

Pipeline order:
  1) subfinder  -> subdomains
  2) dnsx       -> domain/IP resolution
  3) naabu      -> port discovery
  4) httpx      -> HTTP probing (host:port aware)
  5) katana     -> crawl live hosts
  6) gau        -> historical URLs
  7) arjun      -> parameter discovery

Auth credentials from cfg.auth_headers_flags are injected into httpx and katana
commands so authenticated endpoints are probed correctly.
"""


from __future__ import annotations

import asyncio
from pathlib import Path

from rich.status import Status

from ghilliesuite_ex.arsenal import TOOL_REGISTRY, build_command
from ghilliesuite_ex.config import cfg as global_cfg
from ghilliesuite_ex.state.models import Endpoint, Host, Service
from ghilliesuite_ex.utils.executor import run_tool, run_tool_to_file
from ghilliesuite_ex.utils.parsers import (
    get_parser,
    parse_subfinder,
    parse_httpx,
    parse_dnsx,
    parse_naabu,
    parse_arjun,
)
from ghilliesuite_ex.utils.scope import is_in_scope, scope_filter_domains, scope_filter_urls
from ghilliesuite_ex.utils.ui import tool_result_panel

from .base import AgentResult, AgentTask, BaseAgent

# ── Temp file locations for inter-tool data handoff ───────────────────────────
_TMP_DIR          = Path("tmp")
_SUBFINDER_OUT    = _TMP_DIR / "subfinder_out.txt"
_DNSX_IN          = _TMP_DIR / "dnsx_in.txt"
_DNSX_OUT         = _TMP_DIR / "dnsx_out.json"
_NAABU_IN         = _TMP_DIR / "naabu_in.txt"
_NAABU_OUT        = _TMP_DIR / "naabu_out.json"
_HTTPX_IN         = _TMP_DIR / "httpx_in.txt"
_HTTPX_OUT        = _TMP_DIR / "httpx_out.json"
_ARJUN_IN         = _TMP_DIR / "arjun_in.txt"
_ARJUN_OUT        = _TMP_DIR / "arjun_out.json"


class ReconAgent(BaseAgent):
    """
    Runs subfinder, gau, httpx, and katana in an optimised DAG order.
    All tools have hitl_required=False so no user confirmation is needed.
    Auth credentials from cfg are injected into httpx and katana.
    """

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        timeout = self.cfg.default_timeout
        items_added = 0

        auth_headers = self.cfg.auth_headers_flags  # [] if no auth configured
        _TMP_DIR.mkdir(parents=True, exist_ok=True)

        # Phase 1: subfinder
        self.console.print(f"[cyan]  Phase 1 - subfinder -> {target}[/cyan]")
        root_domain = target.split("//")[-1].split("/")[0].split(":")[0]
        sf_history: set[str] = getattr(self.cfg, "_subfinder_history", set())
        run_sf = root_domain not in sf_history

        subdomains: list[str] = []
        sf_result = None
        if run_sf:
            sf_cmd = build_command("subfinder", root_domain, output_file=_SUBFINDER_OUT)
            with Status("[cyan]Running subfinder...[/cyan]", console=self.console):
                sf_result = await run_tool_to_file(sf_cmd, _SUBFINDER_OUT, timeout=timeout)
            sf_history.add(root_domain)
            setattr(self.cfg, "_subfinder_history", sf_history)
        else:
            self.console.print(f"[dim]subfinder: skipped (root domain {root_domain} already scanned)[/dim]")

        if sf_result and (sf_result.ok or sf_result.output_file):
            parsed = parse_subfinder(output_path=sf_result.output_file or _SUBFINDER_OUT)
            raw_domains = [r["domain"] for r in parsed]
            subdomains = scope_filter_domains(raw_domains, self.scope)
            for domain in subdomains:
                await self.db.insert_host(Host(domain=domain))
                items_added += 1
            tool_result_panel(
                self.console, "subfinder",
                sf_cmd, sf_result.ok or bool(sf_result.output_file),
                f"Found {len(subdomains)} in-scope subdomain(s)",
            )
        elif sf_result:
            self.console.print(f"[dim]subfinder: {sf_result.error or sf_result.stderr[:100]}[/dim]")

        if not subdomains:
            self.console.print("[yellow]  WARNING: subfinder found no subdomains - falling back to root target[/yellow]")
            subdomains = [root_domain]

        # Phase 2: dnsx
        self.console.print(f"[cyan]  Phase 2 - dnsx resolving {len(subdomains)} host(s)[/cyan]")
        _DNSX_IN.write_text("
".join(subdomains), encoding="utf-8")
        dnsx_cmd = build_command("dnsx", target, input_file=_DNSX_IN, output_file=_DNSX_OUT)
        with Status("[cyan]Running dnsx...[/cyan]", console=self.console):
            dnsx_result = await run_tool_to_file(dnsx_cmd, _DNSX_OUT, timeout=timeout)
        dnsx_rows = []
        if dnsx_result.ok or dnsx_result.output_file:
            dnsx_rows = parse_dnsx(output_path=dnsx_result.output_file or _DNSX_OUT)
            for row in dnsx_rows:
                domain = row.get("domain", "")
                ip = row.get("ip", "")
                if domain and is_in_scope(domain, self.scope):
                    await self.db.upsert_host(Host(domain=domain, ip=ip))
                    items_added += 1
        tool_result_panel(
            self.console, "dnsx",
            dnsx_cmd, dnsx_result.ok or bool(dnsx_result.output_file),
            f"Resolved {len(dnsx_rows)} host(s)",
        )

        # Phase 3: naabu
        self.console.print(f"[cyan]  Phase 3 - naabu scanning ports on {len(subdomains)} host(s)[/cyan]")
        _NAABU_IN.write_text("
".join(subdomains), encoding="utf-8")
        naabu_cmd = build_command("naabu", target, input_file=_NAABU_IN, output_file=_NAABU_OUT)
        with Status("[cyan]Running naabu...[/cyan]", console=self.console):
            naabu_result = await run_tool_to_file(naabu_cmd, _NAABU_OUT, timeout=timeout)

        service_count = 0
        services: list[Service] = []
        if naabu_result.ok or naabu_result.output_file:
            rows = parse_naabu(output_path=naabu_result.output_file or _NAABU_OUT)
            for row in rows:
                host = row.get("host") or ""
                ip = row.get("ip") or ""
                port = int(row.get("port") or 0)
                proto = row.get("proto") or "tcp"
                if not host and ip:
                    host = ip
                if not host or not port:
                    continue
                if not is_in_scope(host, self.scope):
                    continue
                host_id = await self.db.upsert_host(Host(domain=host, ip=ip))
                if host_id:
                    svc = Service(
                        host_id=host_id,
                        port=port,
                        proto=str(proto).lower(),
                        service="",
                        source_tool="naabu",
                    )
                    await self.db.insert_service(svc)
                    services.append(svc)
                    service_count += 1
        tool_result_panel(
            self.console, "naabu",
            naabu_cmd, naabu_result.ok or bool(naabu_result.output_file),
            f"Stored {service_count} service(s)",
        )

        # Phase 4: httpx
        self.console.print("[cyan]  Phase 4 - httpx probing live services[/cyan]")
        httpx_targets: list[str] = []
        if services:
            hosts = {h.id: h for h in await self.db.get_hosts(self.scope)}
            for svc in services:
                h = hosts.get(svc.host_id)
                if not h:
                    continue
                scheme = "https" if svc.port in (443, 8443) else "http"
                httpx_targets.append(f"{scheme}://{h.domain}:{svc.port}")
        else:
            httpx_targets = subdomains[:]

        _HTTPX_IN.write_text("
".join(httpx_targets), encoding="utf-8")
        httpx_cmd = build_command(
            "httpx", target,
            input_file=_HTTPX_IN,
            output_file=_HTTPX_OUT,
            auth_headers=auth_headers,
        )
        with Status("[cyan]httpx probing...[/cyan]", console=self.console):
            httpx_result = await run_tool_to_file(httpx_cmd, _HTTPX_OUT, timeout=timeout)

        live_count = 0
        live_urls: list[str] = []
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
                host_id = await self.db.upsert_host(host)
                items_added += 1
                live_count += 1
                live_urls.append(item["url"])

                if item.get("ai_detected") and host_id:
                    try:
                        await self.db.tag_host(host_id, "ai_detected")
                    except Exception:
                        pass

                if host_id:
                    ep = Endpoint(url=item["url"], source_tool="httpx", host_id=host_id)
                    await self.db.insert_endpoint(ep)

        tool_result_panel(
            self.console, "httpx", httpx_cmd,
            httpx_result.ok or bool(httpx_result.output_file),
            f"Found {live_count} live HTTP service(s)",
        )

        # Optional: gowitness screenshots
        if self.cfg.enable_screenshots and live_urls:
            self.console.print(f"[cyan]  Optional - gowitness screenshots ({len(live_urls)} URL(s))[/cyan]")
            go_in = _TMP_DIR / "gowitness_in.txt"
            go_out = _TMP_DIR / "gowitness_out.json"
            go_in.write_text("
".join(live_urls[:100]), encoding="utf-8")
            gow_cmd = build_command("gowitness", target, input_file=go_in, output_file=go_out)
            with Status("[cyan]Running gowitness...[/cyan]", console=self.console):
                gow_result = await run_tool_to_file(gow_cmd, go_out, timeout=timeout)
            tool_result_panel(
                self.console, "gowitness",
                gow_cmd, gow_result.ok or bool(gow_result.output_file),
                "Screenshots captured (see gowitness output directory).",
            )

        # Phase 5: katana
        live_hosts = await self.db.get_hosts(self.scope)
        katana_urls_found = 0
        for host in live_hosts[:5]:
            url_target = f"https://{host.domain}"
            self.console.print(f"[cyan]  Phase 5 - katana crawling {url_target}[/cyan]")

            if task.tool_name and task.tool_name != "katana":
                self.console.print(f"[dim]  Supervisor specified {task.tool_name} - skipping katana.[/dim]")
                break

            katana_cmd = build_command("katana", url_target, auth_headers=auth_headers)
            with Status(f"[cyan]Crawling {url_target}...[/cyan]", console=self.console):
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

        # Phase 6: gau
        self.console.print(f"[cyan]  Phase 6 - gau historical URLs -> {target}[/cyan]")
        gau_cmd = build_command("gau", target)
        with Status("[cyan]Running gau...[/cyan]", console=self.console):
            gau_result = await run_tool(gau_cmd, timeout=timeout)
        gau_urls_added = 0
        if gau_result.ok:
            parsed_gau = get_parser("gau")(gau_result.stdout)
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
            self.console.print(f"[dim]gau: {gau_result.error or gau_result.stderr[:100]}[/dim]")
        tool_result_panel(
            self.console, "gau",
            gau_cmd, gau_result.ok,
            f"Stored {gau_urls_added} high-value in-scope URL(s)",
        )

        # Phase 7: arjun
        self.console.print("[cyan]  Phase 7 - arjun parameter discovery[/cyan]")
        endpoints = await self.db.get_endpoints(with_params_only=False)
        arjun_targets = [e.url for e in endpoints if e.url][:50]
        arjun_urls_added = 0
        if arjun_targets:
            _ARJUN_IN.write_text("
".join(arjun_targets), encoding="utf-8")
            arjun_cmd = build_command("arjun", target, input_file=_ARJUN_IN, output_file=_ARJUN_OUT)
            with Status("[cyan]Running arjun...[/cyan]", console=self.console):
                arjun_result = await run_tool_to_file(arjun_cmd, _ARJUN_OUT, timeout=timeout)
            if arjun_result.ok or arjun_result.output_file:
                parsed = parse_arjun(output_path=arjun_result.output_file or _ARJUN_OUT)
                for row in parsed:
                    url = row.get("url") or ""
                    params = row.get("params") or []
                    if not url or not params:
                        continue
                    if not is_in_scope(url, self.scope):
                        continue
                    params_str = ",".join(params)
                    await self.db.update_endpoint_params(url, params_str)
                    ep = Endpoint(url=url, params=params_str, source_tool="arjun")
                    await self.db.insert_endpoint(ep)
                    items_added += 1
                    arjun_urls_added += 1
            tool_result_panel(
                self.console, "arjun",
                arjun_cmd, arjun_result.ok or bool(arjun_result.output_file),
                f"Discovered params for {arjun_urls_added} URL(s)",
            )
        else:
            self.console.print("[dim]arjun: no endpoints to analyze.[/dim]")

        return AgentResult(
            agent=self.name,
            status="ok",
            summary=(
                f"Recon complete - {len(subdomains)} subdomains, "
                f"{live_count} live hosts, {service_count} services, "
                f"{katana_urls_found} crawled endpoints. "
                f"(Auth: {'active' if auth_headers else 'none'})"
            ),
            items_added=items_added,
        )
