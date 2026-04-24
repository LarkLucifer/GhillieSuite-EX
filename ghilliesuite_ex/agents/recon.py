"""
ghilliesuite_ex/agents/recon.py
--------------------------------
ReconAgent - coverage-first reconnaissance.

Pipeline order:
  1) subfinder  -> subdomains
  2) httpx      -> HTTP probing (file-based handoff)
  3) katana     -> crawl live hosts (concurrent, file-based JSONL)
  4) gau        -> historical URLs (default add-on stage)
  5) arjun      -> parameter discovery (default add-on stage)
  6) dnsx       -> DNS enrichment (optional)
  7) naabu      -> port scan enrichment (optional)
  8) subzy      -> takeover checks (optional)

Auth credentials from cfg.auth_headers_flags are injected into httpx and katana
commands so authenticated endpoints are probed correctly.
"""


from __future__ import annotations

import asyncio
from pathlib import Path
from urllib.parse import urlsplit

from rich.status import Status

from ghilliesuite_ex.arsenal import build_command
from ghilliesuite_ex.state.models import Endpoint, Finding, Host, Screenshot, Service
from ghilliesuite_ex.utils.executor import run_tool, run_tool_to_file
from ghilliesuite_ex.utils.parsers import (
    get_parser,
    parse_dnsx,
    parse_naabu,
    parse_subfinder,
    parse_arjun,
    parse_gowitness,
)
from ghilliesuite_ex.utils.scope import is_in_scope, scope_filter_domains, filter_in_scope
from ghilliesuite_ex.utils.ui import tool_result_panel

from .base import AgentResult, AgentTask, BaseAgent

# Temp file locations for inter-tool data handoff
_TMP_DIR          = Path("tmp")
_SUBFINDER_OUT    = _TMP_DIR / "subfinder_out.txt"
_HTTPX_IN         = _TMP_DIR / "httpx_in.txt"
_HTTPX_OUT        = _TMP_DIR / "httpx_out.json"
_ARJUN_IN         = _TMP_DIR / "arjun_in.txt"
_ARJUN_OUT        = _TMP_DIR / "arjun_out.json"
_DNSX_IN          = _TMP_DIR / "dnsx_in.txt"
_DNSX_OUT         = _TMP_DIR / "dnsx_out.json"
_NAABU_IN         = _TMP_DIR / "naabu_in.txt"
_NAABU_OUT        = _TMP_DIR / "naabu_out.json"
_SUBZY_IN         = _TMP_DIR / "subzy_in.txt"
_SUBZY_OUT        = _TMP_DIR / "subzy_out.json"

_ARJUN_STATIC_EXTS = (
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp",
    ".css", ".js", ".map",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".ico", ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
    ".mp4", ".mp3", ".avi", ".mov", ".mkv",
)
_ARJUN_SEO_PATHS = ("/page/", "/wp-content/", "/author/", "/tag/", "/category/")
_ARJUN_PRIORITY_MARKERS = (".php", ".aspx", "/api/")


def _is_arjun_priority(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return any(marker in path for marker in _ARJUN_PRIORITY_MARKERS)


def _is_arjun_candidate(url: str) -> bool:
    path = urlsplit(url).path.lower()
    if not path:
        return False
    if any(path.endswith(ext) for ext in _ARJUN_STATIC_EXTS):
        return False
    if not _is_arjun_priority(url):
        if any(seg in path for seg in _ARJUN_SEO_PATHS):
            return False
        if path.endswith("/"):
            return False
    return True


def _get_arjun_base_path(url: str) -> str:
    """Extract unique base path for Blitz deduplication."""
    parts = urlsplit(url)
    path = parts.path
    if not path or path == "/":
        return f"{parts.scheme}://{parts.netloc}/"
    
    # Remove last segment if it looks like a resource or ID
    segments = [s for s in path.split("/") if s]
    if segments:
        last = segments[-1]
        if "." in last or len(last) > 20: # skip filenames or long IDs
            segments = segments[:-1]
            
    base_path = "/".join(segments)
    return f"{parts.scheme}://{parts.netloc}/{base_path}"


class ReconAgent(BaseAgent):
    """
    Runs a file-based core chain:
      subfinder -> httpx -> katana
    then add-on stages:
      gau -> arjun (enabled by default)
      dnsx -> naabu -> subzy (optional toggles)
    All tools have hitl_required=False so no user confirmation is needed.
    Auth credentials from cfg are injected into httpx and katana.
    """

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        timeout = self.cfg.default_timeout
        items_added = 0

        auth_headers = self.cfg.auth_headers_flags  # [] if no auth configured
        _TMP_DIR.mkdir(parents=True, exist_ok=True)
        recon_run_count = int(getattr(self, "_recon_run_count", 0)) + 1
        httpx_history: set[str] = getattr(self, "_httpx_history", set())
        katana_history: set[str] = getattr(self, "_katana_history", set())
        katana_last_crawl_run: dict[str, int] = getattr(self, "_katana_last_crawl_run", {})
        gau_history: set[str] = getattr(self, "_gau_history", set())
        arjun_history: set[str] = getattr(self, "_arjun_history", set())
        dnsx_history: set[str] = getattr(self, "_dnsx_history", set())
        naabu_history: set[str] = getattr(self, "_naabu_history", set())
        subzy_history: set[str] = getattr(self, "_subzy_history", set())

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
        # Phase 2: httpx (file-based handoff from subfinder)
        live_count = 0
        live_urls: list[str] = []
        new_endpoints: list[str] = []
        httpx_targets: list[str] = []
        for domain in subdomains:
            httpx_targets.append(f"http://{domain}")
            httpx_targets.append(f"https://{domain}")

        httpx_targets = filter_in_scope(httpx_targets, self.scope)
        httpx_targets = list(dict.fromkeys(httpx_targets))
        httpx_delta = [url for url in httpx_targets if url not in httpx_history]

        if httpx_delta:
            self.console.print(
                f"[cyan]  Phase 2 - httpx probing {len(httpx_delta)} target(s) from subfinder output[/cyan]"
            )
            _HTTPX_IN.write_text("\n".join(httpx_delta) + "\n", encoding="utf-8")
            httpx_cmd = build_command(
                "httpx",
                target,
                input_file=_HTTPX_IN,
                output_file=_HTTPX_OUT,
                auth_headers=auth_headers,
            )
            with Status("[cyan]Running httpx...[/cyan]", console=self.console):
                httpx_result = await run_tool_to_file(httpx_cmd, _HTTPX_OUT, timeout=timeout)

            if httpx_result.ok or httpx_result.output_file:
                parsed_rows = get_parser("httpx")(output_path=httpx_result.output_file or _HTTPX_OUT)
                for row in parsed_rows:
                    url = str(row.get("url") or "").strip()
                    if not url or not is_in_scope(url, self.scope):
                        continue

                    hostname = urlsplit(url).hostname or ""
                    if not hostname:
                        continue

                    host_id = await self.db.upsert_host(
                        Host(
                            domain=hostname,
                            status_code=int(row.get("status_code") or 0),
                            server=str(row.get("server") or ""),
                            tech_stack=str(row.get("tech_stack") or ""),
                        )
                    )
                    items_added += 1
                    live_count += 1
                    live_urls.append(url)
                    new_endpoints.append(url)

                    if host_id:
                        await self.db.insert_endpoint(
                            Endpoint(
                                url=url,
                                source_tool="httpx",
                                host_id=host_id,
                            )
                        )
            else:
                self.console.print(f"[dim]httpx: {httpx_result.error or httpx_result.stderr[:100]}[/dim]")

            httpx_history.update(httpx_delta)
            tool_result_panel(
                self.console, "httpx",
                httpx_cmd,
                httpx_result.ok or bool(httpx_result.output_file),
                f"Found {live_count} live HTTP service(s)",
            )
        else:
            self.console.print("[dim]httpx: skipped (no new targets)[/dim]")

        # Optional: gowitness screenshots
        if self.cfg.enable_screenshots and live_urls:
            self.console.print(f"[cyan]  Optional - gowitness screenshots ({len(live_urls)} URL(s))[/cyan]")
            go_in = _TMP_DIR / "gowitness_in.txt"
            go_out = _TMP_DIR / "gowitness_out.json"
            go_in.write_text("\n".join(live_urls[:100]), encoding="utf-8")
            gow_cmd = build_command("gowitness", target, input_file=go_in, output_file=go_out)
            with Status("[cyan]Running gowitness...[/cyan]", console=self.console):
                gow_result = await run_tool_to_file(gow_cmd, go_out, timeout=timeout)
            screenshots_added = 0
            if gow_result.ok or gow_result.output_file:
                rows = parse_gowitness(output_path=gow_result.output_file or go_out)
                for row in rows:
                    url = row.get("url") or ""
                    shot_path = row.get("screenshot") or ""
                    title = row.get("title") or ""
                    status = int(row.get("status") or 0)
                    if not url or not shot_path:
                        continue
                    p = Path(shot_path)
                    if not p.is_absolute():
                        # Try resolving relative to gowitness output or cwd
                        for base in (go_out.parent, Path.cwd()):
                            candidate = (base / shot_path).resolve()
                            if candidate.exists():
                                p = candidate
                                break
                    if p.exists():
                        await self.db.insert_screenshot(
                            Screenshot(
                                url=url,
                                path=str(p),
                                title=title,
                                status=status,
                                source_tool="gowitness",
                            )
                        )
                        screenshots_added += 1
            tool_result_panel(
                self.console, "gowitness",
                gow_cmd, gow_result.ok or bool(gow_result.output_file),
                f"Screenshots captured: {screenshots_added}",
            )

        # Phase 3: katana (delta-only, concurrent)
        katana_urls_found = 0
        if task.tool_name and task.tool_name != "katana":
            self.console.print(f"[dim]  Supervisor specified {task.tool_name} - skipping katana.[/dim]")
        else:
            live_hosts = await self.db.get_hosts(self.scope)
            host_by_domain = {h.domain: h for h in live_hosts}
            katana_candidates: list[str] = []
            for url in live_urls:
                base = url.split("#")[0].split("?")[0]
                parts = base.split("/")
                base = "/".join(parts[:3]) if len(parts) >= 3 else base
                if base:
                    katana_candidates.append(base)
            katana_candidates = list(dict.fromkeys(katana_candidates))
            try:
                recrawl_interval = max(1, int(getattr(self.cfg, "katana_recrawl_interval", 3)))
            except Exception:
                recrawl_interval = 3

            katana_delta: list[str] = []
            for url_target in katana_candidates:
                if url_target not in katana_history:
                    katana_delta.append(url_target)
                    continue
                last_run = int(katana_last_crawl_run.get(url_target, 0) or 0)
                if (recon_run_count - last_run) >= recrawl_interval:
                    katana_delta.append(url_target)

            if katana_delta:
                # Determine max concurrent targets - turbo mode doubles the limit
                try:
                    from ghilliesuite_ex.config import cfg as _cfg
                    _max_t = int(getattr(_cfg, "katana_max_targets", 10))
                    if getattr(_cfg, "turbo_mode", False):
                        _max_t = min(_max_t * 2, 50)
                except Exception:
                    _max_t = 10

                targets_to_crawl = katana_delta[:_max_t]
                self.console.print(
                    f"[cyan]  Phase 3 - katana crawling {len(targets_to_crawl)} target(s) "
                    f"concurrently (max={_max_t}, delta={len(katana_delta)})[/cyan]"
                )

                _sem = asyncio.Semaphore(_max_t)

                async def _run_katana_single(url_target: str):
                    """Crawl a single target with Katana using file-based JSONL output."""
                    import hashlib
                    _safe = hashlib.md5(url_target.encode()).hexdigest()[:8]
                    _out_path = _TMP_DIR / f"katana_{_safe}.jsonl"
                    async with _sem:
                        _cmd = build_command(
                            "katana", url_target,
                            output_file=_out_path,
                            auth_headers=auth_headers,
                        )
                        return url_target, await run_tool_to_file(_cmd, _out_path, timeout=timeout)

                with Status("[cyan]Concurrent Katana crawl in progress...[/cyan]", console=self.console):
                    crawl_tasks = [_run_katana_single(u) for u in targets_to_crawl]
                    crawl_results = await asyncio.gather(*crawl_tasks, return_exceptions=True)

                try:
                    max_eps_per_target = max(1, int(getattr(self.cfg, "katana_max_endpoints_per_target", 4000)))
                except Exception:
                    max_eps_per_target = 4000

                for item in crawl_results:
                    if isinstance(item, Exception):
                        self.console.print(f"[dim]katana: task error - {item}[/dim]")
                        continue
                    url_target, katana_result = item
                    if katana_result.error:
                        self.console.print(f"[dim]katana [{url_target[:40]}]: {katana_result.error[:80]}[/dim]")
                        continue

                    parsed_eps = get_parser("katana")(
                        output="",
                        output_path=katana_result.output_file,
                    )
                    domain = url_target.split("//")[-1].split("/")[0]
                    host = host_by_domain.get(domain)
                    inserted_for_target = 0
                    seen_target_urls: set[str] = set()
                    for ep_item in parsed_eps:
                        ep_url = str(ep_item.get("url") or "")
                        if not ep_url or ep_url in seen_target_urls:
                            continue
                        if not is_in_scope(ep_url, self.scope):
                            continue
                        if inserted_for_target >= max_eps_per_target:
                            break

                        seen_target_urls.add(ep_url)
                        ep = Endpoint(
                            url=ep_url,
                            params=ep_item.get("params", ""),
                            source_tool="katana",
                            host_id=host.id if host else None,
                        )
                        await self.db.insert_endpoint(ep)
                        items_added += 1
                        katana_urls_found += 1
                        inserted_for_target += 1
                        new_endpoints.append(ep_url)

                    if inserted_for_target >= max_eps_per_target:
                        self.console.print(
                            f"[dim]katana [{url_target[:40]}]: endpoint cap reached ({max_eps_per_target})[/dim]"
                        )

                katana_history.update(targets_to_crawl)
                for crawled_target in targets_to_crawl:
                    katana_last_crawl_run[crawled_target] = recon_run_count
                tool_result_panel(
                    self.console, "katana",
                    build_command("katana", targets_to_crawl[0], output_file=_TMP_DIR / "katana_preview.jsonl"),
                    True,
                    f"Crawled {len(targets_to_crawl)} targets -> {katana_urls_found} high-value endpoint(s)",
                )
            else:
                self.console.print("[dim]katana: skipped (no new live URLs)[/dim]")

        # Phase 4: gau (delta-only, existing add-on)
        gau_urls_added = 0
        if root_domain not in gau_history:
            self.console.print(f"[cyan]  Phase 4 - gau historical URLs -> {target}[/cyan]")
            gau_cmd = build_command("gau", target)
            with Status("[cyan]Running gau...[/cyan]", console=self.console):
                gau_result = await run_tool(gau_cmd, timeout=timeout)
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
                        new_endpoints.append(entry["url"])
                gau_history.add(root_domain)
            else:
                self.console.print(f"[dim]gau: {gau_result.error or gau_result.stderr[:100]}[/dim]")
            tool_result_panel(
                self.console, "gau",
                gau_cmd, gau_result.ok,
                f"Stored {gau_urls_added} high-value in-scope URL(s)",
            )
        else:
            self.console.print("[dim]gau: skipped (already ran for target)[/dim]")

        # Phase 5: arjun (delta-only, existing add-on)
        arjun_urls_added = 0
        raw_targets = [u for u in new_endpoints if u and u not in arjun_history]
        raw_targets = [u for u in raw_targets if is_in_scope(u, self.scope)]
        filtered_targets = [u for u in raw_targets if _is_arjun_candidate(u)]
        filtered_targets = list(dict.fromkeys(filtered_targets))
        # Arjun Blitz Deduplication: Group by base path
        seen_bases: set[str] = set()
        blitz_targets = []
        for u in filtered_targets:
            base = _get_arjun_base_path(u)
            if base not in seen_bases:
                seen_bases.add(base)
                blitz_targets.append(u)
        
        priority_targets = [u for u in blitz_targets if _is_arjun_priority(u)]
        other_targets = [u for u in blitz_targets if u not in priority_targets]
        arjun_targets = (priority_targets + other_targets)[:20] # Increased cap for Blitz
        if arjun_targets:
            self.console.print("[cyan]  Phase 5 - arjun parameter discovery[/cyan]")
            _ARJUN_IN.write_text("\n".join(arjun_targets) + "\n", encoding="utf-8")
            arjun_cmd = build_command(
                "arjun",
                target,
                input_file=_ARJUN_IN,
                output_file=_ARJUN_OUT,
                extra_args=["-t", "10"],
            )
            with Status("[cyan]Running arjun (list mode)...[/cyan]", console=self.console):
                arjun_result = await run_tool_to_file(arjun_cmd, _ARJUN_OUT, timeout=300)
            parsed_rows: list[dict] = []
            if arjun_result.ok or arjun_result.output_file:
                parsed_rows = parse_arjun(output_path=arjun_result.output_file or _ARJUN_OUT)
            else:
                self.console.print("[dim]arjun list mode failed; falling back to concurrent per-URL mode.[/dim]")
                sem = asyncio.Semaphore(5)

                async def _run_single(idx: int, url: str):
                    per_out = _TMP_DIR / f"arjun_out_{idx}.json"
                    per_cmd = ["arjun", "-u", url, "-oJ", str(per_out), "-t", "10"]
                    async with sem:
                        per_res = await run_tool_to_file(per_cmd, per_out, timeout=300)
                    return per_out, per_res

                with Status("[cyan]Running arjun (per-URL, concurrent)...[/cyan]", console=self.console):
                    results = await asyncio.gather(
                        *[_run_single(idx, url) for idx, url in enumerate(arjun_targets)],
                        return_exceptions=False,
                    )

                for per_out, per_res in results:
                    if per_res.ok or per_res.output_file:
                        parsed_rows.extend(parse_arjun(output_path=per_res.output_file or per_out))

            for row in parsed_rows:
                url = row.get("url") or ""
                params = row.get("params") or []
                if not url or not params:
                    continue
                if not is_in_scope(url, self.scope):
                    continue
                
                params_str = ",".join(sorted(set(params)))
                # Update existing endpoint or insert new one with these params
                await self.db.update_endpoint_params(url, params_str)
                # Ensure it exists in DB (in case update_endpoint_params found nothing to update)
                ep = Endpoint(url=url, params=params_str, source_tool="arjun")
                await self.db.insert_endpoint(ep)
                
                items_added += 1
                arjun_urls_added += 1

            if parsed_rows:
                arjun_history.update(arjun_targets)
            arjun_ok = (arjun_result.ok or bool(arjun_result.output_file) or bool(parsed_rows))
            tool_result_panel(
                self.console, "arjun",
                arjun_cmd, arjun_ok,
                f"Discovered params for {arjun_urls_added} URL(s)",
            )
        else:
            self.console.print("[dim]arjun: skipped (no new endpoints)[/dim]")

        # Optional add-on: dnsx (explicitly gated by config/CLI toggle)
        dnsx_hosts_added = 0
        if getattr(self.cfg, "recon_enable_dnsx", False):
            if root_domain in dnsx_history:
                self.console.print("[dim]dnsx: skipped (already ran for target)[/dim]")
            else:
                try:
                    dnsx_targets = list(
                        dict.fromkeys(d for d in subdomains if d and is_in_scope(d, self.scope))
                    )
                    if dnsx_targets:
                        self.console.print(
                            f"[cyan]  Optional - dnsx DNS enrichment ({len(dnsx_targets)} domain(s))[/cyan]"
                        )
                        _DNSX_IN.write_text("\n".join(dnsx_targets) + "\n", encoding="utf-8")
                        dnsx_cmd = build_command(
                            "dnsx",
                            target,
                            input_file=_DNSX_IN,
                            output_file=_DNSX_OUT,
                        )
                        with Status("[cyan]Running dnsx...[/cyan]", console=self.console):
                            dnsx_result = await run_tool_to_file(dnsx_cmd, _DNSX_OUT, timeout=timeout)

                        if dnsx_result.ok or dnsx_result.output_file:
                            rows = parse_dnsx(output_path=dnsx_result.output_file or _DNSX_OUT)
                            for row in rows:
                                domain = str(row.get("domain") or "").strip().lower()
                                ip = str(row.get("ip") or "").strip()
                                if not domain or not is_in_scope(domain, self.scope):
                                    continue
                                await self.db.upsert_host(Host(domain=domain, ip=ip))
                                items_added += 1
                                dnsx_hosts_added += 1
                            dnsx_history.add(root_domain)
                        else:
                            self.console.print(
                                f"[dim]dnsx: {dnsx_result.error or dnsx_result.stderr[:100]}[/dim]"
                            )

                        tool_result_panel(
                            self.console, "dnsx",
                            dnsx_cmd, dnsx_result.ok or bool(dnsx_result.output_file),
                            f"Resolved {dnsx_hosts_added} in-scope host/IP mapping(s)",
                        )
                    else:
                        self.console.print("[dim]dnsx: skipped (no in-scope domains)[/dim]")
                except Exception as exc:
                    self.console.print(f"[dim]dnsx: non-blocking error - {exc}[/dim]")
        else:
            self.console.print("[dim]dnsx: skipped (RECON_ENABLE_DNSX=0)[/dim]")

        # Optional add-on: naabu (explicitly gated by config/CLI toggle)
        naabu_services_added = 0
        if getattr(self.cfg, "recon_enable_naabu", False):
            if root_domain in naabu_history:
                self.console.print("[dim]naabu: skipped (already ran for target)[/dim]")
            else:
                try:
                    host_rows = await self.db.get_hosts(self.scope)
                    naabu_targets = list(dict.fromkeys(h.domain for h in host_rows if h.domain))
                    if not naabu_targets:
                        naabu_targets = list(
                            dict.fromkeys(d for d in subdomains if d and is_in_scope(d, self.scope))
                        )

                    if naabu_targets:
                        self.console.print(
                            f"[cyan]  Optional - naabu service scan ({len(naabu_targets)} host(s))[/cyan]"
                        )
                        _NAABU_IN.write_text("\n".join(naabu_targets) + "\n", encoding="utf-8")
                        naabu_cmd = build_command(
                            "naabu",
                            target,
                            input_file=_NAABU_IN,
                            output_file=_NAABU_OUT,
                        )
                        with Status("[cyan]Running naabu...[/cyan]", console=self.console):
                            naabu_result = await run_tool_to_file(naabu_cmd, _NAABU_OUT, timeout=timeout)

                        if naabu_result.ok or naabu_result.output_file:
                            parsed_rows = parse_naabu(output_path=naabu_result.output_file or _NAABU_OUT)

                            hosts_now = await self.db.get_hosts(self.scope)
                            host_by_domain = {h.domain: h for h in hosts_now}
                            ip_to_domain: dict[str, str] = {}
                            for h in hosts_now:
                                for ip_candidate in str(h.ip or "").split(","):
                                    ip_candidate = ip_candidate.strip()
                                    if ip_candidate:
                                        ip_to_domain[ip_candidate] = h.domain

                            for row in parsed_rows:
                                host_raw = str(row.get("host") or "").strip().lower()
                                ip_raw = str(row.get("ip") or "").strip()
                                port = int(row.get("port") or 0)
                                proto = str(row.get("proto") or "tcp").strip().lower() or "tcp"
                                if port <= 0:
                                    continue

                                domain = host_raw
                                if domain and not is_in_scope(domain, self.scope):
                                    domain = ip_to_domain.get(ip_raw, "")
                                if not domain:
                                    domain = ip_to_domain.get(ip_raw, "")
                                if not domain or not is_in_scope(domain, self.scope):
                                    continue

                                host = host_by_domain.get(domain)
                                host_id = host.id if host else 0
                                if not host_id:
                                    host_id = await self.db.upsert_host(Host(domain=domain, ip=ip_raw))
                                    host_by_domain[domain] = Host(id=host_id, domain=domain, ip=ip_raw)

                                if host_id:
                                    await self.db.insert_service(
                                        Service(
                                            host_id=host_id,
                                            port=port,
                                            proto=proto,
                                            source_tool="naabu",
                                        )
                                    )
                                    items_added += 1
                                    naabu_services_added += 1

                            naabu_history.add(root_domain)
                        else:
                            self.console.print(
                                f"[dim]naabu: {naabu_result.error or naabu_result.stderr[:100]}[/dim]"
                            )

                        tool_result_panel(
                            self.console, "naabu",
                            naabu_cmd, naabu_result.ok or bool(naabu_result.output_file),
                            f"Stored {naabu_services_added} service record(s)",
                        )
                    else:
                        self.console.print("[dim]naabu: skipped (no hosts to scan)[/dim]")
                except Exception as exc:
                    self.console.print(f"[dim]naabu: non-blocking error - {exc}[/dim]")
        else:
            self.console.print("[dim]naabu: skipped (RECON_ENABLE_NAABU=0)[/dim]")

        # Optional add-on: subzy (explicitly gated by config/CLI toggle)
        subzy_findings_added = 0
        if getattr(self.cfg, "recon_enable_subzy", False):
            if root_domain in subzy_history:
                self.console.print("[dim]subzy: skipped (already ran for target)[/dim]")
            else:
                try:
                    subzy_targets = list(
                        dict.fromkeys(d for d in subdomains if d and is_in_scope(d, self.scope))
                    )
                    if not subzy_targets:
                        subzy_targets = list(
                            dict.fromkeys(h.domain for h in await self.db.get_hosts(self.scope) if h.domain)
                        )

                    if subzy_targets:
                        self.console.print(
                            f"[cyan]  Optional - subzy takeover check ({len(subzy_targets)} domain(s))[/cyan]"
                        )
                        _SUBZY_IN.write_text("\n".join(subzy_targets) + "\n", encoding="utf-8")
                        subzy_cmd = build_command(
                            "subzy",
                            target,
                            input_file=_SUBZY_IN,
                            output_file=_SUBZY_OUT,
                        )
                        with Status("[cyan]Running subzy...[/cyan]", console=self.console):
                            subzy_result = await run_tool_to_file(subzy_cmd, _SUBZY_OUT, timeout=timeout)

                        if subzy_result.ok or subzy_result.output_file:
                            parsed_rows = get_parser("subzy")(output_path=subzy_result.output_file or _SUBZY_OUT)
                            for row in parsed_rows:
                                domain = str(row.get("domain") or "").strip().lower()
                                status = str(row.get("status") or "").strip()
                                service = str(row.get("service") or "").strip()
                                vulnerable = bool(row.get("vulnerable")) or ("vulnerable" in status.lower())
                                if not domain or not vulnerable or not is_in_scope(domain, self.scope):
                                    continue

                                evidence = f"subzy flagged potential takeover on {domain}"
                                if service:
                                    evidence += f" (service: {service})"

                                await self.db.insert_finding(
                                    Finding(
                                        tool="subzy",
                                        target=domain,
                                        severity="high",
                                        title="Potential subdomain takeover",
                                        evidence=evidence,
                                        reproducible_steps=(
                                            "1. Verify dangling DNS/CNAME for the subdomain.\n"
                                            "2. Attempt provider ownership claim workflow.\n"
                                            "3. Re-check HTTP response and takeover proof."
                                        ),
                                        raw_output=f"status={status}; service={service}",
                                    )
                                )
                                items_added += 1
                                subzy_findings_added += 1
                            subzy_history.add(root_domain)
                        else:
                            self.console.print(
                                f"[dim]subzy: {subzy_result.error or subzy_result.stderr[:100]}[/dim]"
                            )

                        tool_result_panel(
                            self.console, "subzy",
                            subzy_cmd, subzy_result.ok or bool(subzy_result.output_file),
                            f"Potential takeover findings stored: {subzy_findings_added}",
                        )
                    else:
                        self.console.print("[dim]subzy: skipped (no in-scope subdomains)[/dim]")
                except Exception as exc:
                    self.console.print(f"[dim]subzy: non-blocking error - {exc}[/dim]")
        else:
            self.console.print("[dim]subzy: skipped (RECON_ENABLE_SUBZY=0)[/dim]")

        setattr(self, "_httpx_history", httpx_history)
        setattr(self, "_katana_history", katana_history)
        setattr(self, "_katana_last_crawl_run", katana_last_crawl_run)
        setattr(self, "_recon_run_count", recon_run_count)
        setattr(self, "_gau_history", gau_history)
        setattr(self, "_arjun_history", arjun_history)
        setattr(self, "_dnsx_history", dnsx_history)
        setattr(self, "_naabu_history", naabu_history)
        setattr(self, "_subzy_history", subzy_history)

        return AgentResult(
            agent=self.name,
            status="ok",
            summary=(
                f"Recon complete - {len(subdomains)} subdomains, "
                f"{live_count} live hosts, "
                f"{katana_urls_found} crawled endpoints. "
                f"(Auth: {'active' if auth_headers else 'none'})"
            ),
            items_added=items_added,
        )

