"""
ghilliesuite_ex/utils/nuclei.py
--------------------------------
Utility helpers for Nuclei maintenance and targeted CVE scans.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass
class NucleiUpdateResult:
    ok: bool
    stdout: str = ""
    stderr: str = ""
    error: str = ""


def update_nuclei_templates(timeout: int = 120) -> NucleiUpdateResult:
    """
    Update nuclei templates (CVE feeds) prior to a hunt.
    Uses subprocess.run as a dedicated maintenance step.
    """
    try:
        res = subprocess.run(
            ["nuclei", "-ut"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        ok = res.returncode == 0
        return NucleiUpdateResult(
            ok=ok,
            stdout=res.stdout.strip(),
            stderr=res.stderr.strip(),
            error="" if ok else (res.stderr.strip() or res.stdout.strip()),
        )
    except subprocess.TimeoutExpired:
        return NucleiUpdateResult(
            ok=False,
            error=f"nuclei -ut timed out after {timeout}s",
        )
    except FileNotFoundError:
        return NucleiUpdateResult(
            ok=False,
            error="Binary 'nuclei' not found on PATH",
        )
    except Exception as exc:  # noqa: BLE001
        return NucleiUpdateResult(
            ok=False,
            error=f"Unexpected error: {exc}",
        )
