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
import inspect
import random
from pathlib import Path
from urllib.parse import urlsplit

from rich.status import Status

from ghilliesuite_ex.arsenal import TOOL_REGISTRY, build_command
from ghilliesuite_ex.config import cfg as global_cfg
from ghilliesuite_ex.state.models import Endpoint, Host, Service, Screenshot
from ghilliesuite_ex.utils.executor import run_tool, run_tool_to_file
from ghilliesuite_ex.utils.parsers import (
    get_parser,
    parse_subfinder,
    parse_dnsx,
    parse_naabu,
    parse_arjun,
    parse_gowitness,
)
from ghilliesuite_ex.utils.scope import is_in_scope, scope_filter_domains, scope_filter_urls, filter_in_scope
from ghilliesuite_ex.utils.ui import tool_result_panel

from .base import AgentResult, AgentTask, BaseAgent

import httpx

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

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
]

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


def _headers_from_flags(flags: list[str]) -> dict[str, str]:
    """Convert ['-H', 'Header: value', ...] into a headers dict."""
    headers: dict[str, str] = {}
    if not flags:
        return headers
    it = iter(flags)
    for tok in it:
        if tok != "-H":
            continue
        try:
            hv = next(it)
        except StopIteration:
            break
        if ":" in hv:
            key, val = hv.split(":", 1)
            headers[key.strip()] = val.strip()
    return headers


async def _probe_url(
    session: Any,
    url: str,
    sem: asyncio.Semaphore,
) -> dict[str, str | int] | None:
    """Probe a URL for liveness using either curl_cffi or httpx."""
    async with sem:
        from ghilliesuite_ex.config import cfg as _cfg
        if _cfg.recon_jitter and not _cfg.turbo_mode:
            await asyncio.sleep(random.uniform(0.5, 1.5))
        
        async def _do_get():
            # curl_cffi session has 'impersonate' attribute
            if hasattr(session, "impersonate"):
                ua = random.choice(_USER_AGENTS)
                headers = {
                    "User-Agent": ua,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                }
                response = session.get(
                    url,
                    timeout=10,
                    allow_redirects=_cfg.allow_redirects,
                    headers=headers,
                    verify=False,
                )
                if inspect.isawaitable(response):
                    response = await response
                return response
            else:
                # httpx client
                ua = random.choice(_USER_AGENTS)
                return await session.get(url, timeout=10, follow_redirects=_cfg.allow_redirects, headers={"User-Agent": ua})

        try:
            resp = await _do_get()
            
            # Extract basic metadata
            server = resp.headers.get("server", "") or ""
            powered = resp.headers.get("x-powered-by", "") or ""
            tech_parts = []
            if server: tech_parts.append(server)
            if powered and powered not in tech_parts: tech_parts.append(powered)
            
            return {
                "url": str(resp.url),
                "status_code": int(resp.status_code),
                "server": server,
                "tech_stack": ",".join(tech_parts),
            }
        except Exception as exc:
            return {"url": url, "error": str(exc)}


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
        dnsx_history: set[str] = getattr(self, "_dnsx_history", set())
        naabu_history: set[str] = getattr(self, "_naabu_history", set())
        httpx_history: set[str] = getattr(self, "_httpx_history", set())
        katana_history: set[str] = getattr(self, "_katana_history", set())
        gau_history: set[str] = getattr(self, "_gau_history", set())
        arjun_history: set[str] = getattr(self, "_arjun_history", set())

        # Phase 1: subfinder
        self.console.print(f"[cyan]  Phase 1 - subfinder -> {target}[/cyan]")
        root_domain = target.split("//")[-1].split("/")[0].split(":")[0]
        sf_history: set[str] = getattr(self.cfg, "_subfinder_history", set())
        run_sf = root_domain not in sf_history

        subdomains: list[str] = []
        new_subdomains: list[str] = []
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
            new_subdomains = [d for d in subdomains if d not in dnsx_history]
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

        # Phase 2: dnsx (delta-only)
        dnsx_rows: list[dict] = []
        dnsx_targets = new_subdomains or [d for d in subdomains if d not in dnsx_history]
        if dnsx_targets:
            self.console.print(f"[cyan]  Phase 2 - dnsx resolving {len(dnsx_targets)} new host(s)[/cyan]")
            _DNSX_IN.write_text("\n".join(dnsx_targets), encoding="utf-8")
            dnsx_cmd = build_command("dnsx", target, input_file=_DNSX_IN, output_file=_DNSX_OUT)
            with Status("[cyan]Running dnsx...[/cyan]", console=self.console):
                dnsx_result = await run_tool_to_file(dnsx_cmd, _DNSX_OUT, timeout=timeout)
            if dnsx_result.ok or dnsx_result.output_file:
                dnsx_rows = parse_dnsx(output_path=dnsx_result.output_file or _DNSX_OUT)
                for row in dnsx_rows:
                    domain = row.get("domain", "")
                    ip = row.get("ip", "")
                    if domain and is_in_scope(domain, self.scope):
                        await self.db.upsert_host(Host(domain=domain, ip=ip))
                        items_added += 1
                dnsx_history.update(dnsx_targets)
            tool_result_panel(
                self.console, "dnsx",
                dnsx_cmd, dnsx_result.ok or bool(dnsx_result.output_file),
                f"Resolved {len(dnsx_rows)} host(s)",
            )
        else:
            self.console.print("[dim]dnsx: skipped (no new domains)[/dim]")

        # Phase 2.5: subzy (Subdomain Takeover - delta-only)
        subzy_added = 0
        if dnsx_targets:
            self.console.print(f"[cyan]  Phase 2.5 - subzy takeover check on {len(dnsx_targets)} host(s)[/cyan]")
            subzy_cmd = build_command("subzy", target, input_file=_DNSX_IN, output_file=_TMP_DIR / "subzy_out.json")
            with Status("[cyan]Running subzy...[/cyan]", console=self.console):
                subzy_result = await run_tool_to_file(subzy_cmd, _TMP_DIR / "subzy_out.json", timeout=timeout)
            
            if subzy_result.ok or subzy_result.output_file:
                rows = get_parser("subzy")(output_path=subzy_result.output_file or (_TMP_DIR / "subzy_out.json"))
                for row in rows:
                    # Logic to insert takeover finding
                    if row.get("vulnerable"):
                        from ghilliesuite_ex.state.models import Finding
                        await self.db.insert_finding(Finding(
                            tool="subzy",
                            target=row["url"],
                            severity="high",
                            title=f"Subdomain Takeover Detected — {row.get('service')}",
                            evidence=f"Service: {row.get('service')}\nDetails: {row.get('raw')}",
                            reproducible_steps=f"1. Host: {row['url']}\n2. Fingerprint: {row.get('service')}\n3. Verify: visit manually.",
                            raw_output=row.get("raw", "")
                        ))
                        subzy_added += 1
                tool_result_panel(
                    self.console, "subzy",
                    subzy_cmd, subzy_result.ok or bool(subzy_result.output_file),
                    f"Check complete - found {subzy_added} potential takeover(s)",
                )

        # Phase 3: naabu (delta-only)
        service_count = 0
        services: list[Service] = []
        naabu_seed = [row.get("domain") or row.get("ip") for row in dnsx_rows if (row.get("domain") or row.get("ip"))]
        naabu_targets = [h for h in naabu_seed if h not in naabu_history]
        if naabu_targets:
            self.console.print(f"[cyan]  Phase 3 - naabu scanning ports on {len(naabu_targets)} new host(s)[/cyan]")
            _NAABU_IN.write_text("\n".join(naabu_targets), encoding="utf-8")
            naabu_cmd = build_command("naabu", target, input_file=_NAABU_IN, output_file=_NAABU_OUT)
            with Status("[cyan]Running naabu...[/cyan]", console=self.console):
                naabu_result = await run_tool_to_file(naabu_cmd, _NAABU_OUT, timeout=timeout)
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
                naabu_history.update(naabu_targets)
            tool_result_panel(
                self.console, "naabu",
                naabu_cmd, naabu_result.ok or bool(naabu_result.output_file),
                f"Stored {service_count} service(s)",
            )
        else:
            self.console.print("[dim]naabu: skipped (no new hosts)[/dim]")

        # Phase 4: HTTP probing (python httpx, delta-only)
        live_count = 0
        live_urls: list[str] = []
        new_endpoints: list[str] = []
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
            for domain in subdomains:
                httpx_targets.append(f"http://{domain}")
                httpx_targets.append(f"https://{domain}")

        httpx_targets = filter_in_scope(httpx_targets, self.scope)
        httpx_delta = [t for t in httpx_targets if t not in httpx_history]
        if httpx_delta:
            self.console.print("[cyan]  Phase 4 - Advanced HTTP probing (Chrome Fingerprint)[/cyan]")
            
            from curl_cffi import requests as _requests
            # Lower concurrency to 10 for home router stability (bypassed if turbo)
            max_concurrency = 50 if self.cfg.turbo_mode else 10
            sem = asyncio.Semaphore(max_concurrency)
            
            try:
                from curl_cffi.requests import AsyncSession as CurlSession
                use_curl = True
            except ImportError:
                use_curl = False
                self.console.print("[yellow]  WARNING: curl_cffi not found. Stealth reduced (falling back to httpx).[/yellow]")

            # Lower concurrency to 10 for home router stability (boosted only in turbo)
            max_concurrency = 50 if self.cfg.turbo_mode else 10
            sem = asyncio.Semaphore(max_concurrency)
            
            if use_curl:
                session = CurlSession(impersonate="chrome120", verify=False)
                tasks = [_probe_url(session, url, sem) for url in httpx_delta]
                with Status("[cyan]Probing with curl_cffi...[/cyan]", console=self.console):
                    results = await asyncio.gather(*tasks, return_exceptions=True)
            else:
                import httpx
                async with httpx.AsyncClient(verify=False, follow_redirects=self.cfg.allow_redirects) as session:
                    tasks = [_probe_url(session, url, sem) for url in httpx_delta]
                    with Status("[cyan]Probing with httpx...[/cyan]", console=self.console):
                        results = await asyncio.gather(*tasks, return_exceptions=True)

            probe_errors = 0
            max_probe_errors = 20
            for item in results:
                if not item or isinstance(item, Exception):
                    continue
                if isinstance(item, dict) and item.get("error"):
                    if probe_errors < max_probe_errors:
                        self.console.print(
                            f"[dim]httpx probe failed: {item.get('url','')} — {str(item.get('error'))[:160]}[/dim]"
                        )
                    probe_errors += 1
                    continue
                url = str(item.get("url") or "")
                if not url or not is_in_scope(url, self.scope):
                    continue
                hostname = urlsplit(url).hostname or ""
                if not hostname:
                    continue
                host = Host(
                    domain=hostname,
                    status_code=int(item.get("status_code") or 0),
                    server=str(item.get("server") or ""),
                    tech_stack=str(item.get("tech_stack") or ""),
                )
                host_id = await self.db.upsert_host(host)
                items_added += 1
                live_count += 1
                live_urls.append(url)
                new_endpoints.append(url)

                if host_id:
                    ep = Endpoint(url=url, source_tool="httpx", host_id=host_id)
                    await self.db.insert_endpoint(ep)

            httpx_history.update(httpx_delta)

            tool_result_panel(
                self.console, "httpx",
                ["python", "async_http_probe"],
                True,
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

        # Phase 5: katana (delta-only, concurrent)
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
            katana_delta = [u for u in katana_candidates if u not in katana_history]

            if katana_delta:
                # Determine max concurrent targets — turbo mode doubles the limit
                try:
                    from ghilliesuite_ex.config import cfg as _cfg
                    _max_t = int(getattr(_cfg, "katana_max_targets", 10))
                    if getattr(_cfg, "turbo_mode", False):
                        _max_t = min(_max_t * 2, 50)
                except Exception:
                    _max_t = 10

                targets_to_crawl = katana_delta[:_max_t]
                self.console.print(
                    f"[cyan]  Phase 5 - katana crawling {len(targets_to_crawl)} target(s) "
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

                for item in crawl_results:
                    if isinstance(item, Exception):
                        self.console.print(f"[dim]katana: task error — {item}[/dim]")
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
                    for ep_item in parsed_eps:
                        if is_in_scope(ep_item["url"], self.scope):
                            ep = Endpoint(
                                url=ep_item["url"],
                                params=ep_item.get("params", ""),
                                source_tool="katana",
                                host_id=host.id if host else None,
                            )
                            await self.db.insert_endpoint(ep)
                            items_added += 1
                            katana_urls_found += 1
                            new_endpoints.append(ep_item["url"])

                katana_history.update(targets_to_crawl)
                tool_result_panel(
                    self.console, "katana",
                    build_command("katana", targets_to_crawl[0], output_file=_TMP_DIR / "katana_preview.jsonl"),
                    True,
                    f"Crawled {len(targets_to_crawl)} targets → {katana_urls_found} high-value endpoint(s)",
                )
            else:
                self.console.print("[dim]katana: skipped (no new live URLs)[/dim]")

        # Phase 6: gau (delta-only)
        gau_urls_added = 0
        if root_domain not in gau_history:
            self.console.print(f"[cyan]  Phase 6 - gau historical URLs -> {target}[/cyan]")
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

        # Phase 7: arjun (delta-only)
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
            self.console.print("[cyan]  Phase 7 - arjun parameter discovery[/cyan]")
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

        setattr(self, "_dnsx_history", dnsx_history)
        setattr(self, "_naabu_history", naabu_history)
        setattr(self, "_httpx_history", httpx_history)
        setattr(self, "_katana_history", katana_history)
        setattr(self, "_gau_history", gau_history)
        setattr(self, "_arjun_history", arjun_history)

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
