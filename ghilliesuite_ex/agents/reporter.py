"""
ghilliesuite_ex/agents/reporter.py
───────────────────────
ReporterAgent — queries the SQLite DB and writes structured reports.

Outputs:
  • JSON report    — reports/<target>_<timestamp>.json
  • Markdown report — reports/<target>_<timestamp>.md
    Structured: Critical → High → Medium → Low → Info
    Includes: reproducible steps, evidence, raw output snippets.
  • HTML report    — reports/<target>_<timestamp>.html
    Tailwind CSS dark theme, AI plain-English summaries per finding,
    collapsible technical sections, BOLA/IDOR & AI advisory section.
  • Rich terminal table — displayed to console immediately.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from rich.rule import Rule

from ghilliesuite_ex.state.models import Finding
from ghilliesuite_ex.utils.redaction import redact_text
from ghilliesuite_ex.utils.ui import SEVERITY_COLORS, findings_table

from .base import AgentResult, AgentTask, BaseAgent

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _safe_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        try:
            value.encode("utf-8")
            return value
        except UnicodeEncodeError:
            return value.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    try:
        text = str(value)
    except Exception:
        return ""
    try:
        text.encode("utf-8")
        return text
    except UnicodeEncodeError:
        return text.encode("utf-8", errors="replace").decode("utf-8", errors="replace")


def _report_safe_text(value) -> str:
    return redact_text(_safe_text(value))


def _extract_evidence_paths(text: str) -> tuple[str, str]:
    """Extract evidence request/response file paths from a finding's evidence text."""
    text = _safe_text(text)
    req_path = ""
    res_path = ""
    for line in (text or "").splitlines():
        if "Request:" in line:
            req_path = line.split("Request:", 1)[-1].strip()
        if "Response:" in line:
            res_path = line.split("Response:", 1)[-1].strip()
    return req_path, res_path


class ReporterAgent(BaseAgent):
    """Compiles all DB findings into a JSON + Markdown report."""

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        findings = await self.db.get_findings()
        hosts = await self.db.get_hosts()
        endpoints = await self.db.get_endpoints()
        screenshots = await self.db.get_screenshots()

        # ── Terminal tables ────────────────────────────────────────────────
        if not findings:
            findings_table(self.console, findings)
        else:
            stealth_findings = [f for f in findings if f.tool == "stealth_payload"]
            standard_findings = [f for f in findings if f.tool != "stealth_payload"]
            if standard_findings:
                findings_table(self.console, standard_findings, title="Findings Summary")
            if stealth_findings:
                findings_table(
                    self.console,
                    stealth_findings,
                    title="AI Stealth Probes & WAF Bypasses",
                )

        # ── Resolve output dir ─────────────────────────────────────────────
        output_dir = Path("reports")
        if getattr(self.cfg, "output_dir", None):
            output_dir = Path(self.cfg.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        now_utc = datetime.now(timezone.utc)
        ts = now_utc.strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace(".", "_").replace("/", "_").replace(":", "")
        base_name = f"{safe_target}_{ts}"
        ai_status = getattr(self.cfg, "ai_status_message", "AI triage disabled")
        ai_reason = getattr(self.cfg, "ai_disabled_reason", "")

        # ── JSON Report ────────────────────────────────────────────────────
        json_path = output_dir / f"{base_name}.json"
        report_data = {
            "target": target,
            "generated_at": now_utc.isoformat(),
            "scope": self.scope,
            "scan_config": {
                "ai_triage": {
                    "enabled": bool(getattr(self.cfg, "ai_enabled", False) and self.ai is not None),
                    "status": ai_status,
                    "reason": ai_reason,
                },
                "js_deep_inspection": {
                    "js_max_workers": self.cfg.js_max_workers,
                    "js_max_files": self.cfg.js_max_files,
                    "js_llm_concurrency": self.cfg.js_llm_concurrency,
                    "js_snippet_max_len": self.cfg.js_snippet_max_len,
                    "js_http_timeout": self.cfg.js_http_timeout,
                    "js_llm_timeout": self.cfg.js_llm_timeout,
                },
                "force_exploit": bool(getattr(self.cfg, "force_exploit", False)),
            },
            "stats": {
                "hosts": len(hosts),
                "endpoints": len(endpoints),
                "findings": len(findings),
            },
            "findings": [
                {
                    "id": f.id,
                    "tool": _report_safe_text(f.tool),
                    "target": _report_safe_text(f.target),
                    "severity": _report_safe_text(f.severity),
                    "title": _report_safe_text(f.title),
                    "evidence": _report_safe_text(f.evidence),
                    "reproducible_steps": _report_safe_text(f.reproducible_steps),
                    "raw_output_excerpt": _report_safe_text(f.raw_output)[:500],
                    "timestamp": _report_safe_text(f.timestamp),
                    "evidence_request_path": _extract_evidence_paths(f.evidence)[0],
                    "evidence_response_path": _extract_evidence_paths(f.evidence)[1],
                }
                for f in findings
            ],
            "hosts": [
                {"domain": h.domain, "status_code": h.status_code, "tech_stack": h.tech_stack}
                for h in hosts
            ],
            "screenshots": [
                {"url": s.url, "path": s.path, "title": s.title, "status": s.status}
                for s in screenshots
            ],
        }
        json_path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")

        # ── Markdown Report ────────────────────────────────────────────────
        md_path = output_dir / f"{base_name}.md"
        md_lines = [
            f"# GhillieSuite-EX Bug Bounty Report",
            f"",
            f"**Target:** `{target}`  ",
            f"**Generated:** {now_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            f"**Scope:** {', '.join(self.scope)}  ",
            f"**AI Triage:** {ai_status}" + (f" ({ai_reason})" if ai_reason else "") + "  ",
            f"",
            f"---",
            f"",
            f"## Summary",
            f"",
            f"| Metric | Count |",
            f"|--------|-------|",
            f"| Hosts discovered | {len(hosts)} |",
            f"| Endpoints mapped | {len(endpoints)} |",
            f"| Total findings   | {len(findings)} |",
            f"",
            f"## Execution Flags",
            f"",
            f"| Flag | Value |",
            f"|------|-------|",
            f"| `force_exploit` | {bool(getattr(self.cfg, 'force_exploit', False))} |",
            f"",
            f"## JS Deep Inspection Config",
            f"",
            f"| Setting | Value |",
            f"|---------|-------|",
            f"| `js_max_workers` | {self.cfg.js_max_workers} |",
            f"| `js_max_files` | {self.cfg.js_max_files} |",
            f"| `js_llm_concurrency` | {self.cfg.js_llm_concurrency} |",
            f"| `js_snippet_max_len` | {self.cfg.js_snippet_max_len} |",
            f"| `js_http_timeout` | {self.cfg.js_http_timeout} |",
            f"| `js_llm_timeout` | {self.cfg.js_llm_timeout} |",
            f"",
        ]

        # Split stealth probes from standard findings
        stealth_findings = [f for f in findings if f.tool == "stealth_payload"]
        standard_findings = [f for f in findings if f.tool != "stealth_payload"]

        # Group by severity (standard findings only)
        by_severity: dict[str, list[Finding]] = {s: [] for s in SEVERITY_ORDER}
        for f in standard_findings:
            bucket = f.severity.lower()
            by_severity.setdefault(bucket, []).append(f)

        for severity in SEVERITY_ORDER:
            bucket = by_severity.get(severity, [])
            if not bucket:
                continue
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(severity, "⚫")
            md_lines += [
                f"## {emoji} {severity.capitalize()} Findings ({len(bucket)})",
                "",
            ]
            for i, f in enumerate(bucket, start=1):
                req_path, res_path = _extract_evidence_paths(f.evidence)
                title = _report_safe_text(f.title)
                tool = _report_safe_text(f.tool)
                target_v = _report_safe_text(f.target)
                severity_v = _report_safe_text(f.severity)
                timestamp_v = _report_safe_text(f.timestamp)
                evidence_v = _report_safe_text(f.evidence or "N/A")
                steps_v = _report_safe_text(f.reproducible_steps or "N/A")
                raw_v = _report_safe_text(f.raw_output)[:500] if f.raw_output else "N/A"
                md_lines += [
                    f"### {i}. {title}",
                    f"",
                    f"| Field | Value |",
                    f"|-------|-------|",
                    f"| **Tool** | `{tool}` |",
                    f"| **Target** | `{target_v}` |",
                    f"| **Severity** | **{severity_v.upper()}** |",
                    f"| **Timestamp** | {timestamp_v} |",
                    f"",
                    f"**Evidence:**",
                    f"```",
                    evidence_v,
                    f"```",
                    f"Evidence Request: `{req_path}`" if req_path else "",
                    f"Evidence Response: `{res_path}`" if res_path else "",
                    f"",
                    f"**Reproducible Steps:**",
                    f"",
                    steps_v,
                    f"",
                    f"**Raw Output (excerpt):**",
                    f"```",
                    raw_v,
                    f"```",
                    f"",
                    f"---",
                    f"",
                ] 

        # Stealth probes section (separate from standard findings)
        if stealth_findings:
            md_lines += [
                f"## AI Stealth Probes & WAF Bypasses ({len(stealth_findings)})",
                "",
                "Targeted low-noise probes executed via Python requests. Includes WAF bypass attempts and response evidence.",
                "",
            ]
            for i, f in enumerate(stealth_findings, start=1):
                req_path, res_path = _extract_evidence_paths(f.evidence)
                md_lines += [
                    f"### {i}. {_report_safe_text(f.title)}",
                    f"",
                    f"| Field | Value |",
                    f"|-------|-------|",
                    f"| **Tool** | `{_report_safe_text(f.tool)}` |",
                    f"| **Target** | `{_report_safe_text(f.target)}` |",
                    f"| **Severity** | **{_report_safe_text(f.severity).upper()}** |",
                    f"| **Timestamp** | {_report_safe_text(f.timestamp)} |",
                    f"",
                    f"**Evidence:**",
                    f"```",
                    _report_safe_text(f.evidence or "N/A"),
                    f"```",
                    f"Evidence Request: `{req_path}`" if req_path else "",
                    f"Evidence Response: `{res_path}`" if res_path else "",
                    f"",
                    f"**Reproducible Steps:**",
                    f"",
                    _report_safe_text(f.reproducible_steps or "N/A"),
                    f"",
                    f"**Raw Output (excerpt):**",
                    f"```",
                    _report_safe_text(f.raw_output[:500] if f.raw_output else "N/A"),
                    f"```",
                    f"",
                    f"---",
                    f"",
                ]

        # Hosts appendix
        if hosts:
            md_lines += [
                f"## Appendix — Discovered Hosts",
                f"",
                f"| Domain | Status | Tech Stack |",
                f"|--------|--------|------------|",
            ]
            for h in hosts:
                md_lines.append(f"| `{h.domain}` | {h.status_code} | {h.tech_stack} |")
            md_lines.append("")

        # Screenshots appendix
        if screenshots:
            md_lines += [
                f"## Appendix â€” Screenshots",
                f"",
                f"| URL | Screenshot Path | Status |",
                f"|-----|------------------|--------|",
            ]
            for s in screenshots:
                md_lines.append(f"| `{s.url}` | `{s.path}` | {s.status} |")
            md_lines.append("")

        md_path.write_text("\n".join(md_lines), encoding="utf-8")

        self.console.print()
        self.console.print(Rule("[bold bright_green]✔  Report saved[/bold bright_green]", style="bright_green"))
        self.console.print(f"  JSON: [underline]{json_path.resolve()}[/underline]")
        self.console.print(f"  MD:   [underline]{md_path.resolve()}[/underline]")
        self.console.print(
            f"[dim]  JS Deep Inspection config: workers={self.cfg.js_max_workers}, "
            f"llm_concurrency={self.cfg.js_llm_concurrency}, "
            f"snippet_max_len={self.cfg.js_snippet_max_len}, "
            f"http_timeout={self.cfg.js_http_timeout}s, "
            f"llm_timeout={self.cfg.js_llm_timeout}s[/dim]"
        )

        # ── HTML Report ────────────────────────────────────────────────────
        try:
            from ghilliesuite_ex.utils.reporter import HtmlReporter
            html_reporter = HtmlReporter(
                db=self.db,
                ai_client=self.ai,
                console=self.console,
                config=self.cfg,
            )
            html_path = await html_reporter.generate(
                target=target,
                scope=self.scope,
                output_dir=output_dir,
            )
            self.console.print(f"  HTML: [underline]{html_path.resolve()}[/underline]")
        except Exception as exc:
            self.console.print(f"[yellow]  ⚠ HTML report failed (continuing): {exc}[/yellow]")

        self.console.print()

        return AgentResult(
            agent=self.name,
            status="ok",
            summary=f"Report written — {len(findings)} finding(s) across {len(hosts)} host(s).",
            items_added=0,
        )
