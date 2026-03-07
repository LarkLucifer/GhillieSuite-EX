"""
ghilliesuite_ex/agents/reporter.py
───────────────────────
ReporterAgent — queries the SQLite DB and writes structured reports.

Outputs:
  • JSON report  — reports/<target>_<timestamp>.json
  • Markdown report — reports/<target>_<timestamp>.md
    Structured: Critical → High → Medium → Low → Info
    Includes: reproducible steps, evidence, raw output snippets.
  • Rich terminal table — displayed to console immediately.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

from rich.rule import Rule

from ghilliesuite_ex.state.models import Finding
from ghilliesuite_ex.utils.ui import SEVERITY_COLORS, findings_table

from .base import AgentResult, AgentTask, BaseAgent

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


class ReporterAgent(BaseAgent):
    """Compiles all DB findings into a JSON + Markdown report."""

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        findings = await self.db.get_findings()
        hosts = await self.db.get_hosts()
        endpoints = await self.db.get_endpoints()

        # ── Terminal table ─────────────────────────────────────────────────
        findings_table(self.console, findings)

        # ── Resolve output dir ─────────────────────────────────────────────
        output_dir = Path("reports")
        output_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace(".", "_").replace("/", "_").replace(":", "")
        base_name = f"{safe_target}_{ts}"

        # ── JSON Report ────────────────────────────────────────────────────
        json_path = output_dir / f"{base_name}.json"
        report_data = {
            "target": target,
            "generated_at": datetime.utcnow().isoformat(),
            "scope": self.scope,
            "stats": {
                "hosts": len(hosts),
                "endpoints": len(endpoints),
                "findings": len(findings),
            },
            "findings": [
                {
                    "id": f.id,
                    "tool": f.tool,
                    "target": f.target,
                    "severity": f.severity,
                    "title": f.title,
                    "evidence": f.evidence,
                    "reproducible_steps": f.reproducible_steps,
                    "raw_output_excerpt": f.raw_output[:500],
                    "timestamp": f.timestamp,
                }
                for f in findings
            ],
            "hosts": [
                {"domain": h.domain, "status_code": h.status_code, "tech_stack": h.tech_stack}
                for h in hosts
            ],
        }
        json_path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")

        # ── Markdown Report ────────────────────────────────────────────────
        md_path = output_dir / f"{base_name}.md"
        md_lines = [
            f"# GhillieSuite-EX Bug Bounty Report",
            f"",
            f"**Target:** `{target}`  ",
            f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            f"**Scope:** {', '.join(self.scope)}  ",
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
        ]

        # Group by severity
        by_severity: dict[str, list[Finding]] = {s: [] for s in SEVERITY_ORDER}
        for f in findings:
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
                md_lines += [
                    f"### {i}. {f.title}",
                    f"",
                    f"| Field | Value |",
                    f"|-------|-------|",
                    f"| **Tool** | `{f.tool}` |",
                    f"| **Target** | `{f.target}` |",
                    f"| **Severity** | **{f.severity.upper()}** |",
                    f"| **Timestamp** | {f.timestamp} |",
                    f"",
                    f"**Evidence:**",
                    f"```",
                    f.evidence or "N/A",
                    f"```",
                    f"",
                    f"**Reproducible Steps:**",
                    f"",
                    f.reproducible_steps or "N/A",
                    f"",
                    f"**Raw Output (excerpt):**",
                    f"```",
                    f.raw_output[:500] if f.raw_output else "N/A",
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

        md_path.write_text("\n".join(md_lines), encoding="utf-8")

        self.console.print()
        self.console.print(Rule("[bold bright_green]✔  Report saved[/bold bright_green]", style="bright_green"))
        self.console.print(f"  JSON: [underline]{json_path.resolve()}[/underline]")
        self.console.print(f"  MD:   [underline]{md_path.resolve()}[/underline]")
        self.console.print()

        return AgentResult(
            agent=self.name,
            status="ok",
            summary=f"Report written — {len(findings)} finding(s) across {len(hosts)} host(s).",
            items_added=0,
        )
