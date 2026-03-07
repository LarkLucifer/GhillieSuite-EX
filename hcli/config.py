"""
hcli/config.py
──────────────
Centralised configuration loader.

All runtime constants are gathered here so every module imports from a single
source of truth.  Call ``validate_config()`` once at startup to fail fast if
required environment variables are missing.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

# ── Load .env from the directory where the CLI is invoked ──────────────────
load_dotenv(dotenv_path=Path.cwd() / ".env", override=False)
load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env", override=False)


# ── Config dataclass populated from env ───────────────────────────────────
@dataclass
class Config:
    # AI
    gemini_api_key: str = field(default_factory=lambda: os.getenv("GEMINI_API_KEY", ""))
    openai_api_key: str = field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))

    # CVE / NVD
    nvd_api_key: str = field(default_factory=lambda: os.getenv("NVD_API_KEY", ""))

    # Execution
    max_agent_loops: int = field(
        default_factory=lambda: int(os.getenv("MAX_AGENT_LOOPS", "15"))
    )
    default_timeout: int = field(
        default_factory=lambda: int(os.getenv("DEFAULT_TIMEOUT", "180"))
    )

    # DB
    db_path: str = field(
        default_factory=lambda: os.getenv("DB_PATH", ".hcli_state.db")
    )

    # Tools that ALWAYS require Human-in-the-Loop confirmation
    hitl_tools: frozenset[str] = field(
        default_factory=lambda: frozenset({"sqlmap", "dalfox"})
    )

    # Nuclei severities that also require HitL
    nuclei_hitl_severities: frozenset[str] = field(
        default_factory=lambda: frozenset({"critical"})
    )


# Global singleton — other modules import this directly
cfg = Config()


def validate_config(ai_provider: str = "gemini") -> None:
    """
    Raise a descriptive RuntimeError if required secrets are missing.
    Call this once in ``main.py`` before starting the agent loop.
    """
    errors: list[str] = []

    if ai_provider == "gemini" and not cfg.gemini_api_key:
        errors.append(
            "GEMINI_API_KEY is not set. "
            "Get one at https://aistudio.google.com/app/apikey and add it to .env"
        )
    elif ai_provider == "openai" and not cfg.openai_api_key:
        errors.append(
            "OPENAI_API_KEY is not set. Add it to .env"
        )

    if errors:
        raise RuntimeError("\n".join(errors))
