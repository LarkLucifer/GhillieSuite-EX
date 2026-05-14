"""
Helpers for writing lightweight per-run metadata artifacts.

These manifests give operators a stable audit trail for preflight failures and
completed runs without storing cookies, tokens, or raw request evidence.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def safe_run_slug(target: str, started_at: datetime) -> str:
    safe_target = (target or "target").replace(".", "_").replace("/", "_").replace(":", "")
    return f"{safe_target}_{started_at.strftime('%Y%m%d_%H%M%S')}"


def build_run_manifest(
    *,
    target: str,
    scope: list[str],
    started_at: datetime,
    finished_at: datetime,
    status: str,
    summary: str,
    execution_profile: str,
    ai_enabled: bool,
    ai_provider: str,
    ai_status_message: str,
    ai_disabled_reason: str,
    output_dir: str,
    evidence_dir: str,
    db_path: str,
    runtime_flags: dict[str, Any],
    tooling: dict[str, Any] | None = None,
    counts: dict[str, int] | None = None,
    failure_stage: str | None = None,
    target_session: dict[str, Any] | None = None,
) -> dict[str, Any]:
    finished_at_utc = finished_at.astimezone(timezone.utc)
    started_at_utc = started_at.astimezone(timezone.utc)
    duration_seconds = max(
        0.0,
        round((finished_at_utc - started_at_utc).total_seconds(), 3),
    )
    manifest: dict[str, Any] = {
        "target": target,
        "scope": list(scope),
        "started_at": started_at_utc.isoformat(),
        "finished_at": finished_at_utc.isoformat(),
        "duration_seconds": duration_seconds,
        "status": status,
        "summary": summary,
        "failure_stage": failure_stage or "",
        "execution_profile": execution_profile,
        "ai": {
            "enabled": ai_enabled,
            "provider": ai_provider,
            "status": ai_status_message,
            "reason": ai_disabled_reason,
        },
        "paths": {
            "output_dir": output_dir,
            "evidence_dir": evidence_dir,
            "db_path": db_path,
        },
        "runtime_flags": dict(runtime_flags),
        "tooling": tooling or {},
        "counts": counts or {},
        "target_session": target_session or {},
        "notes": [
            "This manifest intentionally excludes cookies, auth headers, and raw HTTP evidence.",
        ],
    }
    return manifest


def write_run_manifest(output_dir: str | Path, run_slug: str, manifest: dict[str, Any]) -> Path:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    manifest_path = output_path / f"{run_slug}_run.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest_path
