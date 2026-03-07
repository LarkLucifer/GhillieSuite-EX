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
import html as _html
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console

from ghilliesuite_ex.config import Config, cfg as global_cfg
from ghilliesuite_ex.state.db import StateDB
from ghilliesuite_ex.state.models import Finding, Host, Endpoint


# ── Severity metadata ─────────────────────────────────────────────────────────
_SEV_META: dict[str, dict[str, str]] = {
    "critical": {"color": "red",    "badge": "bg-red-600",    "border": "border-red-500",  "ring": "ring-red-500",  "emoji": "🔴"},
    "high":     {"color": "orange", "badge": "bg-orange-500", "border": "border-orange-400","ring": "ring-orange-400","emoji": "🟠"},
    "medium":   {"color": "yellow", "badge": "bg-yellow-500", "border": "border-yellow-400","ring": "ring-yellow-400","emoji": "🟡"},
    "low":      {"color": "blue",   "badge": "bg-blue-500",   "border": "border-blue-400", "ring": "ring-blue-400", "emoji": "🔵"},
    "info":     {"color": "gray",   "badge": "bg-gray-500",   "border": "border-gray-400", "ring": "ring-gray-400", "emoji": "⚪"},
}
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# ── Advisory tool names (passive, rendered in separate section) ───────────────
_ADVISORY_TOOLS = frozenset({"bola_check", "ai_advisory"})


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

        self.console.print(f"[cyan]  Generating AI summaries for {len(findings)} finding(s)…[/cyan]")
        enriched = await self._enrich_findings(findings, hosts)

        html_content = _render_html(
            target=target,
            scope=scope,
            generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            findings=enriched,
            hosts=hosts,
            endpoints=endpoints,
        )

        html_path.write_text(html_content, encoding="utf-8")
        self.console.print(f"  HTML: [underline]{html_path.resolve()}[/underline]")
        return html_path

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

            enriched.append({
                "id":                 f.id,
                "tool":               f.tool,
                "target":             f.target,
                "severity":           f.severity.lower(),
                "title":              f.title,
                "evidence":           f.evidence,
                "reproducible_steps": f.reproducible_steps,
                "timestamp":          f.timestamp,
                "what_is_it":         title_cache[f.title].get("what_is_it", ""),
                "impact":             title_cache[f.title].get("impact", ""),
                "remediation":        title_cache[f.title].get("remediation", ""),
                "host_status":        host_status,
                "host_tech":          host_tech,
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
) -> str:
    total = len(findings)
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in _SEVERITY_ORDER}

    # Separate technical findings from passive advisories
    tech_findings = [f for f in findings if f["tool"] not in _ADVISORY_TOOLS]
    advisories    = [f for f in findings if f["tool"] in _ADVISORY_TOOLS]

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
    details[open] .chevron {{ transform: rotate(180deg); }}
    .chevron {{ transition: transform 0.2s ease; display: inline-block; }}
    pre {{ white-space: pre-wrap; word-break: break-word; }}
  </style>
</head>
<body class="bg-gray-950 text-gray-100 min-h-screen">

  <!-- ── Header ─────────────────────────────────────────────────────────── -->
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

    <!-- ── Dashboard ──────────────────────────────────────────────────────── -->
    <section>
      <h2 class="text-lg font-semibold text-gray-300 mb-4 uppercase tracking-widest text-xs">Executive Summary</h2>
      <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
        {_stat_card("Total Findings", str(total), "bg-gray-800", "text-white")}
        {_stat_card("Critical", str(counts['critical']), "bg-red-950 border border-red-700", "text-red-400")}
        {_stat_card("High", str(counts['high']), "bg-orange-950 border border-orange-700", "text-orange-400")}
        {_stat_card("Medium", str(counts['medium']), "bg-yellow-950 border border-yellow-700", "text-yellow-400")}
        {_stat_card("Hosts Found", str(len(hosts)), "bg-gray-800", "text-sky-400")}
        {_stat_card("Endpoints", str(len(endpoints)), "bg-gray-800", "text-violet-400")}
      </div>
    </section>

    <!-- ── Technical Findings ─────────────────────────────────────────────── -->
    <section>
      <h2 class="text-lg font-semibold text-gray-300 mb-5 uppercase tracking-widest text-xs border-b border-gray-800 pb-2">
        Vulnerability Findings ({len(tech_findings)})
      </h2>
      {"".join(_finding_card(f) for f in tech_findings) if tech_findings else _empty_state("No active vulnerabilities detected.")}
    </section>

    <!-- ── Advisories ─────────────────────────────────────────────────────── -->
    {"" if not advisories else f'''
    <section>
      <h2 class="text-lg font-semibold text-gray-300 mb-5 uppercase tracking-widest text-xs border-b border-gray-800 pb-2">
        ⚡ Automated Advisories — BOLA/IDOR & AI Injection ({len(advisories)})
      </h2>
      <p class="text-gray-500 text-sm mb-4">These findings were generated by passive analysis — no active exploit traffic was sent. Verify manually.</p>
      {"".join(_finding_card(f) for f in advisories)}
    </section>'''}

    <!-- ── Hosts appendix ─────────────────────────────────────────────────── -->
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

    <!-- ── High-value endpoints ───────────────────────────────────────────── -->
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
    // Smooth keyboard navigation for details elements
    document.querySelectorAll('details').forEach(d => {{
      d.addEventListener('toggle', () => {{
        d.querySelectorAll('.chevron').forEach(c => {{
          c.style.transform = d.open ? 'rotate(180deg)' : 'rotate(0deg)';
        }});
      }});
    }});
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
    tool_name   = f.get("tool", "")
    target_url  = f.get("target", "")
    h_status    = f.get("host_status", "")
    h_tech      = f.get("host_tech", "")
    is_advisory = tool_name in _ADVISORY_TOOLS

    advisory_badge = '<span class="text-xs bg-purple-700 text-white px-2 py-0.5 rounded-full ml-2">Passive Advisory</span>' if is_advisory else ""
    
    status_str = f"HTTP {h_status}" if h_status else "Status Unknown"
    tech_str = f" • Tech: {h_tech}" if h_tech else ""

    return f"""
    <div class="finding-card bg-gray-900 border-l-4 {border_cls} rounded-xl mb-4 overflow-hidden">
      <div class="px-6 py-4">
        <!-- Header row -->
        <div class="flex items-start justify-between gap-4 mb-3">
          <div class="flex-1">
            <div class="flex items-center gap-2 flex-wrap">
              <span class="{badge_cls} text-white text-xs font-semibold px-2 py-0.5 rounded-full uppercase">{_e(sev)}</span>
              {advisory_badge}
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

        <!-- Evidence & Reproducible Steps (Prominent) -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4 pt-4 border-t border-gray-800">
          <div>
            <p class="text-gray-500 text-xs uppercase font-semibold mb-2">Evidence & Target Details</p>
            <div class="bg-gray-950 border border-gray-800 rounded-lg p-3 space-y-2">
              <p class="text-emerald-400 font-mono text-xs break-all">URL: {target_url}</p>
              <p class="text-gray-400 font-mono text-xs">Response: {status_str}{tech_str}</p>
              <pre class="text-xs text-gray-400 mt-2 overflow-x-auto whitespace-pre-wrap">{evidence}</pre>
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
