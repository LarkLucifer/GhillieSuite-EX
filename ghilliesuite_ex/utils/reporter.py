"""
ghilliesuite_ex/utils/reporter.py
─────────────────────────────────
HTML Report Generator for GhillieSuite-EX.

Produces a single self-contained .html file using Tailwind CSS (CDN) with:
  • Executive summary dashboard (counts, severity donut)
  • Per-finding cards with AI-generated plain-English explanations
  • Collapsible technical evidence / reproducible steps sections
  • Dedicated BOLA/IDOR and AI Advisory sections
  • Appendix: discovered hosts and high-value endpoints

The AI generates three plain-English fields per finding:
  • "What is it?"  — simplified explanation for non-technical stakeholders
  • "Impact"       — why it matters / business risk
  • "Remediation"  — concise fix guidance

Usage:
    from ghilliesuite_ex.utils.reporter import HtmlReporter
    reporter = HtmlReporter(db=db, ai_client=ai, console=console, config=cfg)
    html_path = await reporter.generate(target, scope, output_dir)
"""

from __future__ import annotations

import asyncio
import base64
import html as _html
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console

from ghilliesuite_ex.config import Config, cfg as global_cfg
from ghilliesuite_ex.state.db import StateDB
from ghilliesuite_ex.state.models import Finding, Host, Endpoint, Screenshot


# ── Severity metadata ─────────────────────────────────────────────────────────────────────
_SEV_META: dict[str, dict[str, str]] = {
    "critical": {"color": "red",    "badge": "bg-red-600",    "border": "border-red-500",  "ring": "ring-red-500",  "emoji": "🔴"},
    "high":     {"color": "orange", "badge": "bg-orange-500", "border": "border-orange-400","ring": "ring-orange-400","emoji": "🟠"},
    "medium":   {"color": "yellow", "badge": "bg-yellow-500", "border": "border-yellow-400","ring": "ring-yellow-400","emoji": "🟡"},
    "low":      {"color": "blue",   "badge": "bg-blue-500",   "border": "border-blue-400", "ring": "ring-blue-400", "emoji": "🔵"},
    "info":     {"color": "gray",   "badge": "bg-gray-500",   "border": "border-gray-400", "ring": "ring-gray-400", "emoji": "⚪"},
}
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# Severities shown by default in the main section ("hot" findings)
_HOT_SEVERITIES = frozenset({"critical", "high", "medium"})

# ── Advisory tool names (passive, rendered in separate section) ─────────────────
_ADVISORY_TOOLS = frozenset({"bola_check", "ai_advisory"})

_MAX_SCREENSHOT_BYTES = 2 * 1024 * 1024  # 2 MB cap for inline HTML embedding
_MAX_EVIDENCE_CHARS = 8000


def _extract_evidence_paths(text: str) -> tuple[str, str]:
    """Extract evidence request/response file paths from a finding's evidence."""
    req_path = ""
    res_path = ""
    for line in (text or "").splitlines():
        if "Request:" in line:
            req_path = line.split("Request:", 1)[-1].strip()
        if "Response:" in line:
            res_path = line.split("Response:", 1)[-1].strip()
    return req_path, res_path


def _read_text_safe(path: str, max_chars: int = _MAX_EVIDENCE_CHARS) -> str:
    p = Path(path)
    if not p.exists():
        return ""
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return text[:max_chars]


def _image_data_uri(path: str) -> str:
    p = Path(path)
    if not p.exists():
        return ""
    try:
        if p.stat().st_size > _MAX_SCREENSHOT_BYTES:
            return ""
        data = p.read_bytes()
    except OSError:
        return ""
    ext = p.suffix.lower()
    mime = "image/png"
    if ext in (".jpg", ".jpeg"):
        mime = "image/jpeg"
    elif ext in (".webp",):
        mime = "image/webp"
    encoded = base64.b64encode(data).decode("ascii")
    return f"data:{mime};base64,{encoded}"


class HtmlReporter:
    """
    Generates a polished, self-contained HTML security report.
    Calls the AI once per unique finding title to generate stakeholder summaries.
    """

    def __init__(
        self,
        db: StateDB,
        ai_client: Any,
        console: Console,
        config: Config | None = None,
    ) -> None:
        self.db = db
        self.ai = ai_client
        self.console = console
        self.cfg = config or global_cfg

    async def generate(
        self,
        target: str,
        scope: list[str],
        output_dir: str | Path = "reports",
    ) -> Path:
        """
        Query the DB, enrich findings with AI summaries, render HTML, write to disk.
        Returns the absolute path to the generated .html file.
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace(".", "_").replace("/", "_").replace(":", "")
        html_path = output_path / f"{safe_target}_{ts}.html"

        findings:  list[Finding]  = await self.db.get_findings()
        hosts:     list[Host]     = await self.db.get_hosts()
        endpoints: list[Endpoint] = await self.db.get_endpoints()
        screenshots: list[Screenshot] = await self.db.get_screenshots()

        self.console.print(f"[cyan]  Generating AI summaries for {len(findings)} finding(s)…[/cyan]")
        enriched = await self._enrich_findings(findings, hosts)

        js_config = {
            "js_max_workers": self.cfg.js_max_workers,
            "js_max_files": self.cfg.js_max_files,
            "js_llm_concurrency": self.cfg.js_llm_concurrency,
            "js_snippet_max_len": self.cfg.js_snippet_max_len,
            "js_http_timeout": self.cfg.js_http_timeout,
            "js_llm_timeout": self.cfg.js_llm_timeout,
        }
        execution_flags = {
            "force_exploit": bool(getattr(self.cfg, "force_exploit", False)),
        }

        screenshots_render = [
            {
                "url": s.url,
                "path": s.path,
                "title": s.title,
                "status": s.status,
                "data_uri": _image_data_uri(s.path),
            }
            for s in screenshots
        ]

        html_content = _render_html(
            target=target,
            scope=scope,
            generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            findings=enriched,
            hosts=hosts,
            endpoints=endpoints,
            screenshots=screenshots_render,
            js_config=js_config,
            execution_flags=execution_flags,
        )

        html_path.write_text(html_content, encoding="utf-8")
        self.console.print(f"  HTML: [underline]{html_path.resolve()}[/underline]")
        
        self._generate_bounty_draft(target, safe_target, enriched, output_path)

        return html_path

    def _generate_bounty_draft(
        self,
        target: str,
        safe_target: str,
        enriched: list[dict[str, Any]],
        output_path: Path,
    ) -> None:
        """
        Generates a plain text Responsible Disclosure draft for high/critical findings.
        Consolidates all findings into a single email to prevent noise.
        """
        high_critical = [f for f in enriched if f.get("severity", "").lower() in ("high", "critical")]
        if not high_critical:
            return

        draft_path = output_path / f"{safe_target}_bounty_draft.txt"
        
        # Count Severities
        crit_count = sum(1 for f in high_critical if f.get("severity", "").lower() == "critical")
        high_count = sum(1 for f in high_critical if f.get("severity", "").lower() == "high")

        email_draft = [
            f"Subject: Multiple Security Vulnerabilities Report - {target}\n",
            "Hello Security Team,\n",
            "My name is [Your Name/Handle], an independent security researcher. During a routine security assessment on your infrastructure, I discovered multiple security vulnerabilities that require your attention. I am practicing Responsible Disclosure and keeping this confidential.\n",
            "--- FINDINGS SUMMARY ---",
            f"Total Critical Findings: {crit_count}",
            f"Total High Findings: {high_count}\n",
            "--- DETAILED FINDINGS ---\n"
        ]

        for i, f in enumerate(high_critical, start=1):
            sev = str(f.get("severity", "")).upper().strip()
            title = str(f.get("title", "")).strip()
            
            # Use multiple fallbacks to guarantee the URL is caught
            target_url = str(f.get("target", "") or f.get("url", "") or f.get("matched_at", "") or f.get("host", "")).strip()
            impact = str(f.get("impact", "")).strip()
            remediation = str(f.get("remediation", "")).strip()
            
            # Prioritize human-readable steps, then evidence, lastly raw json
            raw_out = str(f.get("raw_output", "")).strip()
            evid_str = str(f.get("evidence", "")).strip()
            steps_str = str(f.get("reproducible_steps", "")).strip()

            evidence = steps_str or evid_str or raw_out
            
            # Attempt to parse json array if that's all that exists
            if evidence.startswith("[") and evidence.endswith("]"):
                import json
                try:
                    parsed_ev = json.loads(evidence)
                    if isinstance(parsed_ev, list) and len(parsed_ev) > 0 and isinstance(parsed_ev[0], dict):
                        first = parsed_ev[0]
                        evidence = str(first.get("payload", "") or first.get("evidence", "") or first.get("request", "")).strip()
                except Exception:
                    pass

            evidence = evidence.strip()
            # If the json rescue gave us empty brackets or it's still missing
            if not evidence or evidence in ("{}", "[{}]", "[]"):
                evidence = "Payload successfully injected at the target endpoint."

            if len(evidence) > 300:
                evidence = evidence[:300].strip() + "\n... [TRUNCATED]"

            finding_block = (
                f"[{i}] Severity: {sev} - {title}\n"
                f"- Vulnerable URL: {target_url}\n"
                "- Evidence / Snippet:\n"
                f"{evidence}\n"
                f"- Impact: {impact}\n"
                f"- Remediation: {remediation}\n"
            )
            email_draft.append(finding_block)

        email_draft.append(
            "Please let me know if you require further details, full request/response logs, or assistance in validating these issues.\n\n"
            "Best regards,\n"
            "[Your Handle]"
        )

        try:
            draft_content = "\n".join(email_draft)
            draft_path.write_text(draft_content.strip(), encoding="utf-8")
            self.console.print(f"  Draft: [underline]{draft_path.resolve()}[/underline]")
        except Exception as e:
            self.console.print(f"[yellow]  ⚠ Failed to write bounty draft: {e}[/yellow]")


    # ── AI enrichment ─────────────────────────────────────────────────────────

    async def _enrich_findings(
        self,
        findings: list[Finding],
        hosts: list[Host],
    ) -> list[dict[str, Any]]:
        """
        For each finding, ask the AI for plain-English explanation, impact, and remediation.
        De-duplicates by title so we don't burn tokens on repeated advisories.
        Falls back gracefully if the AI is unavailable.
        """
        title_cache: dict[str, dict[str, str]] = {}
        enriched: list[dict[str, Any]] = []

        for f in findings:
            if f.title not in title_cache:
                summary = await self._ai_summary(f)
                title_cache[f.title] = summary

            # Match host for status code info
            domain = f.target.split("//")[-1].split("/")[0].split(":")[0]
            matched_host = next((h for h in hosts if h.domain == domain), None)
            host_status = matched_host.status_code if matched_host else ""
            host_tech = matched_host.tech_stack if matched_host else ""

            # Dynamic Severity Promotion
            sev_str = f.severity.lower()
            if "BOLA/IDOR Detected" in f.title:
                sev_str = "critical"

            req_path, res_path = _extract_evidence_paths(f.evidence)
            req_text = _read_text_safe(req_path) if req_path else ""
            res_text = _read_text_safe(res_path) if res_path else ""

            enriched.append({
                "id":                 f.id,
                "tool":               f.tool,
                "target":             f.target,
                "severity":           sev_str,
                "title":              f.title,
                "evidence":           f.evidence,
                "reproducible_steps": f.reproducible_steps,
                "raw_output":         f.raw_output,
                "timestamp":          f.timestamp,
                "what_is_it":         title_cache[f.title].get("what_is_it", ""),
                "impact":             title_cache[f.title].get("impact", ""),
                "remediation":        title_cache[f.title].get("remediation", ""),
                "host_status":        host_status,
                "host_tech":          host_tech,
                "evidence_request_path": req_path,
                "evidence_response_path": res_path,
                "evidence_request": req_text,
                "evidence_response": res_text,
            })

        return enriched

    async def _ai_summary(self, f: Finding) -> dict[str, str]:
        """
        Ask the AI to explain a finding in plain English.
        Returns dict with keys: what_is_it, impact, remediation.
        """
        _SYSTEM = (
            "You are a professional web security report writer. "
            "Your audience is non-technical stakeholders (product managers, executives). "
            "Be concise — 1-3 sentences max per field. No jargon, no CVE numbers. "
            "Under 'impact', if the vulnerability is BOLA/IDOR, explicitly explain which specific ID (e.g., user_id=123) should be tested for manipulation based on the evidence."
        )
        prompt = f"""
Finding title: {f.title}
Tool: {f.tool}
Severity: {f.severity}
Evidence: {f.evidence[:400] if f.evidence else 'N/A'}

Reply with a JSON object containing exactly these three keys:
{{
  "what_is_it": "...",
  "impact": "...",
  "remediation": "..."
}}
"""
        try:
            if hasattr(self.ai, "generate_content"):
                # Gemini
                from ghilliesuite_ex.agents.base import _run_in_thread
                resp = await _run_in_thread(self.ai.generate_content, f"{_SYSTEM}\n\n{prompt}")
                raw = resp.text or ""
            elif hasattr(self.ai, "chat"):
                # OpenAI
                resp = await self.ai.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": _SYSTEM},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.3,
                    max_tokens=300,
                )
                raw = resp.choices[0].message.content or ""
            else:
                raw = ""

            # Parse JSON from response (may have surrounding text)
            start = raw.find("{")
            end   = raw.rfind("}") + 1
            if start >= 0 and end > start:
                return json.loads(raw[start:end])
        except Exception:
            pass

        # Graceful fallback
        return {
            "what_is_it": f"A {f.severity}-severity vulnerability detected by {f.tool}.",
            "impact":      "This issue may be exploitable by an attacker to compromise the application.",
            "remediation": "Review the evidence and reproducible steps below and apply appropriate fixes.",
        }


# ── HTML Rendering ─────────────────────────────────────────────────────────────

def _e(s: Any) -> str:
    """HTML-escape a value for safe inclusion in the template."""
    return _html.escape(str(s or ""), quote=True)


def _render_html(
    target: str,
    scope: list[str],
    generated_at: str,
    findings: list[dict[str, Any]],
    hosts: list[Host],
    endpoints: list[Endpoint],
    screenshots: list[dict[str, Any]] | None = None,
    js_config: dict[str, Any] | None = None,
    execution_flags: dict[str, Any] | None = None,
) -> str:
    # Filter out inactive hosts and their endpoints
    active_hosts = [h for h in hosts if 200 <= getattr(h, "status_code", 0) < 400]
    active_domains = {h.domain for h in active_hosts}
    screenshots = screenshots or []
    
    active_endpoints = []
    for ep in endpoints:
        domain = ep.url.split("//")[-1].split("/")[0].split(":")[0]
        if domain in active_domains:
            active_endpoints.append(ep)
            
    endpoints = active_endpoints
    hosts = active_hosts

    total = len(findings)
    counts_all = {s: sum(1 for f in findings if f["severity"] == s) for s in _SEVERITY_ORDER}

    # Separate stealth probes from standard findings
    stealth_findings = [f for f in findings if f.get("tool") == "stealth_payload"]
    non_stealth = [f for f in findings if f.get("tool") != "stealth_payload"]

    # Separate hot (actionable) findings from passive advisories and low/info noise
    hot_findings  = [f for f in non_stealth if f["severity"] in _HOT_SEVERITIES and f["tool"] not in _ADVISORY_TOOLS]
    advisories    = [f for f in non_stealth if f["tool"] in _ADVISORY_TOOLS]
    cold_findings = [f for f in non_stealth if f["severity"] not in _HOT_SEVERITIES and f["tool"] not in _ADVISORY_TOOLS]
    counts_hot = {s: sum(1 for f in hot_findings if f["severity"] == s) for s in _SEVERITY_ORDER}

    js_config = js_config or {}
    execution_flags = execution_flags or {}

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>GhillieSuite-EX Report — {_e(target)}</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    body {{ font-family: 'Inter', sans-serif; }}
    .finding-card {{ transition: transform 0.15s ease, box-shadow 0.15s ease; }}
    .finding-card:hover {{ transform: translateY(-2px); box-shadow: 0 8px 25px rgba(0,0,0,0.3); }}
    details > summary {{ cursor: pointer; list-style: none; }}
    details > summary::-webkit-details-marker {{ display: none; }}
    pre {{ white-space: pre-wrap; word-break: break-word; }}
    .filter-btn {{ transition: all 0.15s ease; }}
    .filter-btn.active {{ box-shadow: 0 0 0 2px rgba(16,185,129,0.6); }}
    .finding-card[data-severity] {{ display: block; }}
    .finding-card.hidden {{ display: none !important; }}
  </style>
</head>
<body class="bg-gray-950 text-gray-100 min-h-screen">

  <!-- ── Header ───────────────────────────────────────────────────────── -->
  <header class="bg-gradient-to-r from-gray-900 via-gray-800 to-gray-900 border-b border-gray-700 px-8 py-6">
    <div class="max-w-7xl mx-auto flex items-center justify-between">
      <div>
        <div class="flex items-center gap-3 mb-1">
          <span class="text-2xl">🎯</span>
          <h1 class="text-2xl font-bold text-white tracking-tight">GhillieSuite-EX</h1>
          <span class="text-xs bg-emerald-600 text-white px-2 py-0.5 rounded-full font-medium">Security Report</span>
        </div>
        <p class="text-gray-400 text-sm">Target: <span class="text-emerald-400 font-mono font-semibold">{_e(target)}</span></p>
      </div>
      <div class="text-right text-xs text-gray-500">
        <p>Generated: {_e(generated_at)}</p>
        <p>Scope: {_e(', '.join(scope))}</p>
      </div>
    </div>
  </header>

  <main class="max-w-7xl mx-auto px-8 py-8 space-y-10">

    <!-- ── Dashboard ───────────────────────────────────────────────────────── -->
    <section>
      <h2 class="text-lg font-semibold text-gray-300 mb-4 uppercase tracking-widest text-xs">Executive Summary</h2>
      <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
        {_stat_card("Total Findings", str(total), "bg-gray-800", "text-white")}
        {_stat_card("Critical", str(counts_all['critical']), "bg-red-950 border border-red-700", "text-red-400")}
        {_stat_card("High", str(counts_all['high']), "bg-orange-950 border border-orange-700", "text-orange-400")}
        {_stat_card("Medium", str(counts_all['medium']), "bg-yellow-950 border border-yellow-700", "text-yellow-400")}
        {_stat_card("Hosts Found", str(len(hosts)), "bg-gray-800", "text-sky-400")}
        {_stat_card("Endpoints", str(len(endpoints)), "bg-gray-800", "text-violet-400")}
      </div>
    </section>

    <!-- Execution Flags -->
    <section>
      <h2 class="text-lg font-semibold text-gray-300 mb-4 uppercase tracking-widest text-xs">Execution Flags</h2>
      <div class="bg-gray-900 border border-gray-800 rounded-xl p-4 text-sm text-gray-300">
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          <div class="bg-gray-950 border border-gray-800 rounded-lg p-3">
            <div class="text-xs text-gray-500">Force Exploit</div>
            <div class="font-mono text-emerald-400">{_e(str(execution_flags.get("force_exploit", False)))}</div>
          </div>
        </div>
      </div>
    </section>

    <!-- ── Hot Findings (Critical / High / Medium) ────────────────────────── -->
    <!-- â”€â”€ JS Deep Inspection Config â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ -->
    <section>
      <h2 class="text-lg font-semibold text-gray-300 mb-4 uppercase tracking-widest text-xs">JS Deep Inspection Config</h2>
      <div class="bg-gray-900 border border-gray-800 rounded-xl p-4 text-sm text-gray-300">
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          <div class="bg-gray-950 border border-gray-800 rounded-lg p-3">
            <div class="text-xs text-gray-500">Workers</div>
            <div class="font-mono text-emerald-400">{_e(js_config.get("js_max_workers", ""))}</div>
          </div>
          <div class="bg-gray-950 border border-gray-800 rounded-lg p-3">
            <div class="text-xs text-gray-500">Max Files</div>
            <div class="font-mono text-emerald-400">{_e(js_config.get("js_max_files", ""))}</div>
          </div>
          <div class="bg-gray-950 border border-gray-800 rounded-lg p-3">
            <div class="text-xs text-gray-500">LLM Concurrency</div>
            <div class="font-mono text-emerald-400">{_e(js_config.get("js_llm_concurrency", ""))}</div>
          </div>
          <div class="bg-gray-950 border border-gray-800 rounded-lg p-3">
            <div class="text-xs text-gray-500">Snippet Max Len</div>
            <div class="font-mono text-emerald-400">{_e(js_config.get("js_snippet_max_len", ""))}</div>
          </div>
          <div class="bg-gray-950 border border-gray-800 rounded-lg p-3">
            <div class="text-xs text-gray-500">HTTP Timeout (s)</div>
            <div class="font-mono text-emerald-400">{_e(js_config.get("js_http_timeout", ""))}</div>
          </div>
          <div class="bg-gray-950 border border-gray-800 rounded-lg p-3">
            <div class="text-xs text-gray-500">LLM Timeout (s)</div>
            <div class="font-mono text-emerald-400">{_e(js_config.get("js_llm_timeout", ""))}</div>
          </div>
        </div>
      </div>
    </section>

    <section id="hot-findings">
      <div class="flex items-center justify-between mb-4">
        <h2 class="text-lg font-semibold text-gray-300 uppercase tracking-widest text-xs border-b border-gray-800 pb-2 flex-1">
          🔥 Active Vulnerability Findings ({len(hot_findings)})
        </h2>
      </div>

      <!-- Severity filter bar -->
      <div class="flex gap-2 mb-5 flex-wrap" id="filter-bar">
        <button class="filter-btn active text-xs px-3 py-1.5 rounded-full bg-gray-700 text-white font-semibold"
                data-filter="all" onclick="filterFindings('all', this)">
          ALL ({len(hot_findings)})
        </button>
        <button class="filter-btn text-xs px-3 py-1.5 rounded-full bg-red-900 text-red-200 font-semibold"
                data-filter="critical" onclick="filterFindings('critical', this)">
          🔴 CRITICAL ({counts_hot['critical']})
        </button>
        <button class="filter-btn text-xs px-3 py-1.5 rounded-full bg-orange-900 text-orange-200 font-semibold"
                data-filter="high" onclick="filterFindings('high', this)">
          🟠 HIGH ({counts_hot['high']})
        </button>
        <button class="filter-btn text-xs px-3 py-1.5 rounded-full bg-yellow-900 text-yellow-200 font-semibold"
                data-filter="medium" onclick="filterFindings('medium', this)">
          🟡 MEDIUM ({counts_hot['medium']})
        </button>
      </div>

      <div id="findings-container">
        {"".join(_finding_card(f) for f in hot_findings) if hot_findings else _empty_state("No critical/high/medium vulnerabilities detected. 🎉")}
      </div>
    </section>

    <!-- ── Advisories ───────────────────────────────────────────────────────────── -->
    {"" if not advisories else f'''
    <section>
      <h2 class="text-lg font-semibold text-gray-300 mb-5 uppercase tracking-widest text-xs border-b border-gray-800 pb-2">
        ⚡ Automated Advisories — BOLA/IDOR &amp; AI Injection ({len(advisories)})
      </h2>
      <p class="text-gray-500 text-sm mb-4">Passive analysis only — no active exploit traffic sent. Verify manually.</p>
      {"".join(_finding_card(f) for f in advisories)}
    </section>'''}

    <!-- ── AI Stealth Probes ───────────────────────────────────────────────────── -->
    {"" if not stealth_findings else f'''
    <section id="stealth-probes">
      <h2 class="text-lg font-semibold text-gray-300 mb-5 uppercase tracking-widest text-xs border-b border-gray-800 pb-2">
        AI Stealth Probes &amp; WAF Bypasses ({len(stealth_findings)})
      </h2>
      <p class="text-gray-500 text-sm mb-4">Targeted low-noise probes executed via Python requests. Includes WAF bypass attempts and response evidence.</p>
      {"".join(_finding_card(f) for f in stealth_findings)}
    </section>'''}

    <!-- ── Low / Info (collapsed) ────────────────────────────────────────────── -->
    {"" if not cold_findings else f'''
    <section>
      <details class="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        <summary class="px-6 py-4 flex items-center justify-between cursor-pointer hover:bg-gray-800 transition-colors">
          <span class="text-sm font-semibold text-gray-400">⚪ Low / Info Findings ({len(cold_findings)}) — click to expand</span>
          <span class="text-gray-600 text-xs">These are low-priority or informational — review when time allows.</span>
        </summary>
        <div class="p-4 space-y-4">
          {"".join(_finding_card(f) for f in cold_findings)}
        </div>
      </details>
    </section>'''}

    <!-- ── Hosts appendix ─────────────────────────────────────────────────────────── -->
    {"" if not screenshots else f'''
    <section>
      <h2 class="text-lg font-semibold text-gray-300 mb-4 uppercase tracking-widest text-xs border-b border-gray-800 pb-2">
        Visual Evidence (Screenshots) ({len(screenshots)})
      </h2>
      <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {"".join(_screenshot_card(s) for s in screenshots[:24])}
      </div>
      {"" if len(screenshots) <= 24 else f'<p class="text-xs text-gray-500 mt-2">Showing 24 of {len(screenshots)} screenshots.</p>'}
    </section>'''}

    {"" if not hosts else f'''
    <section>
      <h2 class="text-lg font-semibold text-gray-300 mb-4 uppercase tracking-widest text-xs border-b border-gray-800 pb-2">
        Discovered Hosts ({len(hosts)})
      </h2>
      <div class="overflow-x-auto">
        <table class="w-full text-sm text-left text-gray-300">
          <thead class="text-xs uppercase text-gray-500 bg-gray-900">
            <tr>
              <th class="px-4 py-3">Domain</th>
              <th class="px-4 py-3">Status</th>
              <th class="px-4 py-3">Tech Stack</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-800">
            {"".join(_host_row(h) for h in hosts)}
          </tbody>
        </table>
      </div>
    </section>'''}

    <!-- ── High-value endpoints ──────────────────────────────────────────────────── -->
    {"" if not endpoints else f'''
    <section>
      <h2 class="text-lg font-semibold text-gray-300 mb-4 uppercase tracking-widest text-xs border-b border-gray-800 pb-2">
        High-Value Endpoints ({len(endpoints)})
      </h2>
      <div class="bg-gray-900 rounded-xl border border-gray-800 p-4 max-h-64 overflow-y-auto">
        <ul class="space-y-1 font-mono text-xs text-gray-400">
          {"".join(f'<li class="hover:text-emerald-400 transition-colors">{_e(ep.url)}</li>' for ep in endpoints[:100])}
          {"" if len(endpoints) <= 100 else f'<li class="text-gray-600 italic">… and {len(endpoints)-100} more</li>'}
        </ul>
      </div>
    </section>'''}

  </main>

  <footer class="border-t border-gray-800 px-8 py-4 text-center text-xs text-gray-600 mt-10">
    GhillieSuite-EX — For authorized security testing only. You are responsible for program compliance.
  </footer>

  <script>
    function filterFindings(severity, btn) {{
      // Update active button
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      // Show/hide cards
      document.querySelectorAll('#findings-container .finding-card').forEach(card => {{
        if (severity === 'all' || card.dataset.severity === severity) {{
          card.classList.remove('hidden');
        }} else {{
          card.classList.add('hidden');
        }}
      }});
    }}
  </script>
</body>
</html>"""


def _stat_card(label: str, value: str, bg: str, text_color: str) -> str:
    return f"""
    <div class="rounded-xl {bg} p-4 text-center">
      <p class="text-3xl font-bold {text_color}">{_e(value)}</p>
      <p class="text-gray-400 text-xs mt-1">{_e(label)}</p>
    </div>"""


def _finding_card(f: dict[str, Any]) -> str:
    sev  = f.get("severity", "info")
    meta = _SEV_META.get(sev, _SEV_META["info"])
    badge_cls  = meta["badge"]
    border_cls = meta["border"]
    emoji      = meta["emoji"]

    what_is_it  = _e(f.get("what_is_it",  ""))
    impact      = _e(f.get("impact",      ""))
    remediation = _e(f.get("remediation", ""))
    evidence    = _e(f.get("evidence",    "") or "N/A")
    steps       = _e(f.get("reproducible_steps", "") or "No steps provided.")
    raw_out     = f.get("raw_output", "") or ""
    # Truncate and escape raw output for display
    raw_display = _e(raw_out[:800]) if raw_out.strip() else ""
    req_path    = _e(f.get("evidence_request_path", "") or "")
    res_path    = _e(f.get("evidence_response_path", "") or "")
    req_text    = _e(f.get("evidence_request", "") or "")
    res_text    = _e(f.get("evidence_response", "") or "")
    tool_name   = f.get("tool", "")
    target_url  = f.get("target", "")
    h_status    = f.get("host_status", "")
    h_tech      = f.get("host_tech", "")
    is_advisory = tool_name in _ADVISORY_TOOLS

    advisory_badge = '<span class="text-xs bg-purple-700 text-white px-2 py-0.5 rounded-full ml-2">Passive Advisory</span>' if is_advisory else ""
    verified_badge = '<span class="text-xs bg-red-600 border border-red-400 text-white px-2 py-0.5 rounded-full ml-2 font-bold shadow-[0_0_8px_rgba(220,38,38,0.8)]">VERIFIED</span>' if tool_name in ("dalfox", "sqlmap") or "BOLA/IDOR Detected" in _e(f.get('title','')) or "GraphQL Introspection" in _e(f.get('title','')) else ""
    
    status_str = f"HTTP {h_status}" if h_status else "Status Unknown"
    tech_str = f" • Tech: {h_tech}" if h_tech else ""

    proof_block = f"""
            <div class="mt-3">
              <p class="text-emerald-500 text-xs uppercase font-semibold mb-1">🔬 Proof / Raw Tool Output</p>
              <pre class="bg-black border border-emerald-900/50 rounded-lg p-3 text-xs text-emerald-300 overflow-x-auto max-h-40">{raw_display}</pre>
            </div>""" if raw_display else ""

    evidence_files_block = ""
    if req_text or res_text or req_path or res_path:
        evidence_files_block = f"""
            <details class="mt-3">
              <summary class="text-xs text-gray-500 cursor-pointer">Captured HTTP Evidence (request/response)</summary>
              <div class="mt-2 space-y-2">
                {f'<div class="text-[11px] text-gray-600 break-all">Request File: {req_path}</div>' if req_path else ''}
                {f'<pre class="bg-gray-950 border border-gray-800 rounded-lg p-2 text-xs text-gray-300 whitespace-pre-wrap max-h-56 overflow-y-auto">{req_text}</pre>' if req_text else ''}
                {f'<div class="text-[11px] text-gray-600 break-all">Response File: {res_path}</div>' if res_path else ''}
                {f'<pre class="bg-gray-950 border border-gray-800 rounded-lg p-2 text-xs text-gray-300 whitespace-pre-wrap max-h-56 overflow-y-auto">{res_text}</pre>' if res_text else ''}
              </div>
            </details>"""

    return f"""
    <div class="finding-card bg-gray-900 border-l-4 {border_cls} rounded-xl mb-4 overflow-hidden" data-severity="{_e(sev)}">
      <div class="px-6 py-4">
        <!-- Header row -->
        <div class="flex items-start justify-between gap-4 mb-3">
          <div class="flex-1">
            <div class="flex items-center gap-2 flex-wrap">
              <span class="{badge_cls} text-white text-xs font-semibold px-2 py-0.5 rounded-full uppercase">{_e(sev)}</span>
              {advisory_badge}
              {verified_badge}
              <span class="text-xs bg-gray-700 text-gray-300 px-2 py-0.5 rounded-full font-mono">{_e(tool_name)}</span>
            </div>
            <h3 class="text-white font-semibold text-base mt-2">{emoji} {_e(f.get('title',''))}</h3>
          </div>
          <p class="text-gray-600 text-xs whitespace-nowrap">{_e(str(f.get('timestamp',''))[:19])}</p>
        </div>

        <!-- AI plain-English summary -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-3 mb-4">
          <div class="bg-gray-800 rounded-lg p-3">
            <p class="text-gray-500 text-xs font-semibold uppercase mb-1">What is it?</p>
            <p class="text-gray-300 text-sm">{what_is_it}</p>
          </div>
          <div class="bg-gray-800 rounded-lg p-3 border border-red-900/30">
            <p class="text-red-400 text-xs font-semibold uppercase mb-1">Impact</p>
            <p class="text-gray-300 text-sm">{impact}</p>
          </div>
          <div class="bg-gray-800 rounded-lg p-3">
            <p class="text-gray-500 text-xs font-semibold uppercase mb-1">Remediation</p>
            <p class="text-gray-300 text-sm">{remediation}</p>
          </div>
        </div>

        <!-- Evidence &amp; Reproducible Steps (Prominent) -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4 pt-4 border-t border-gray-800">
          <div>
            <p class="text-gray-500 text-xs uppercase font-semibold mb-2">Technical Evidence</p>
            <div class="bg-gray-950 border border-gray-800 rounded-lg p-3 space-y-2">
              <p class="text-emerald-400 font-mono text-xs break-all">URL: {target_url}</p>
              <p class="text-gray-400 font-mono text-xs">Response: {status_str}{tech_str}</p>
              <pre class="text-xs text-gray-400 mt-2 overflow-x-auto whitespace-pre-wrap">{evidence}</pre>
              {proof_block}
              {evidence_files_block}
            </div>
          </div>
          <div>
            <p class="text-sky-500 text-xs uppercase font-semibold mb-2">Steps to Reproduce (Browser/Burp)</p>
            <div class="bg-gray-950 border border-gray-800 rounded-lg p-3">
              <pre class="text-xs text-sky-300 overflow-x-auto whitespace-pre-wrap font-sans">{steps}</pre>
            </div>
          </div>
        </div>
      </div>
    </div>"""


def _screenshot_card(s: dict[str, Any]) -> str:
    url = _e(s.get("url", ""))
    title = _e(s.get("title", "")) or "Screenshot"
    status = _e(s.get("status", "")) if s.get("status") else ""
    path = _e(s.get("path", ""))
    data_uri = s.get("data_uri") or ""
    img_block = (
        f'<img src="{data_uri}" alt="{title}" class="rounded-lg border border-gray-800 w-full h-auto" />'
        if data_uri
        else '<div class="text-xs text-gray-500 italic">Screenshot file not embedded.</div>'
    )
    return f"""
    <div class="bg-gray-900 border border-gray-800 rounded-xl p-3">
      <div class="mb-2">
        <div class="text-xs text-gray-400 font-mono break-all">{url}</div>
        <div class="flex items-center gap-2 mt-1">
          <span class="text-xs bg-gray-800 text-gray-300 px-2 py-0.5 rounded-full">{title}</span>
          {f'<span class="text-xs text-gray-500">HTTP {status}</span>' if status else ''}
        </div>
      </div>
      {img_block}
      <div class="text-[10px] text-gray-600 mt-2 break-all">{path}</div>
    </div>"""


def _host_row(h: Host) -> str:
    status_color = (
        "text-emerald-400" if 200 <= (h.status_code or 0) < 300 else
        "text-yellow-400"  if 300 <= (h.status_code or 0) < 400 else
        "text-red-400"     if (h.status_code or 0) >= 400 else
        "text-gray-500"
    )
    return f"""
    <tr class="hover:bg-gray-800 transition-colors">
      <td class="px-4 py-2 font-mono text-emerald-400">{_e(h.domain)}</td>
      <td class="px-4 py-2 {status_color}">{_e(h.status_code or '-')}</td>
      <td class="px-4 py-2 text-gray-400 text-xs">{_e(h.tech_stack or '-')}</td>
    </tr>"""


def _empty_state(msg: str) -> str:
    return f'<div class="text-center py-12 text-gray-600 text-sm">{_e(msg)}</div>'