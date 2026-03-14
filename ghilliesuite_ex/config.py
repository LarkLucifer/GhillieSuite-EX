"""
ghilliesuite_ex/config.py
──────────────
Centralised configuration loader with AUTO-DETECT AI provider.

Auto-detection logic (no AI_PROVIDER env var needed):
  1. Check OPENAI_API_KEY — if it starts with 'sk-'  → provider = 'openai'
  2. Check GEMINI_API_KEY — if it starts with 'AIza' → provider = 'gemini'
  3. If BOTH are present: OpenAI takes priority.
  4. If NEITHER is present: fail at validate_config() with a helpful message.

Priority order: OpenAI > Gemini
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

# ── Load .env from the directory where the CLI is invoked, then from project root
load_dotenv(dotenv_path=Path.cwd() / ".env", override=False)
load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env", override=False)


# ── Key-prefix detection constants ─────────────────────────────────────────────
_OPENAI_PREFIX = "sk-"
_GEMINI_PREFIX = "AIza"


def detect_ai_provider() -> tuple[str, str]:
    """
    Inspect environment variables and return (provider_name, api_key).

    Detection rules (evaluated in priority order):
      1. OPENAI_API_KEY starting with 'sk-'   → ('openai', key)
      2. GEMINI_API_KEY starting with 'AIza'  → ('gemini', key)
      3. OPENAI_API_KEY set (any value)        → ('openai', key)  [manual override fallback]
      4. GEMINI_API_KEY set (any value)        → ('gemini', key)  [manual override fallback]
      5. Neither set                           → ('none', '')

    Returns:
        Tuple of (provider: str, active_key: str).
        provider is one of 'openai' | 'gemini' | 'none'.
    """
    openai_key = os.getenv("OPENAI_API_KEY", "").strip()
    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()

    # ── Priority 1: OpenAI key with correct prefix ─────────────────────────
    if openai_key.startswith(_OPENAI_PREFIX):
        return ("openai", openai_key)

    # ── Priority 2: Gemini key with correct prefix ─────────────────────────
    if gemini_key.startswith(_GEMINI_PREFIX):
        return ("gemini", gemini_key)

    # ── Priority 3: OpenAI key present (but unusual prefix — warn at validate)
    if openai_key:
        return ("openai", openai_key)

    # ── Priority 4: Gemini key present (but unusual prefix)
    if gemini_key:
        return ("gemini", gemini_key)

    # ── Nothing found ──────────────────────────────────────────────────────
    return ("none", "")


# ── Config dataclass populated from env ────────────────────────────────────────
@dataclass
class Config:
    # ── Raw keys (both loaded; detect_ai_provider() picks the winner)
    gemini_api_key: str = field(default_factory=lambda: os.getenv("GEMINI_API_KEY", "").strip())
    openai_api_key: str = field(default_factory=lambda: os.getenv("OPENAI_API_KEY", "").strip())

    # ── Auto-detected provider + active key (populated post-init)
    ai_provider: str = field(init=False, default="none")
    active_api_key: str = field(init=False, default="")

    # —— Optional fallback provider (used when primary refuses/blocks)
    ai_fallback_provider: str = field(
        default_factory=lambda: os.getenv("AI_FALLBACK_PROVIDER", "").strip().lower()
    )
    ai_fallback_api_key: str = field(
        default_factory=lambda: os.getenv("AI_FALLBACK_API_KEY", "").strip()
    )
    ai_fallback_base_url: str = field(
        default_factory=lambda: os.getenv("AI_FALLBACK_BASE_URL", "").strip()
    )
    ai_fallback_model: str = field(
        default_factory=lambda: os.getenv("AI_FALLBACK_MODEL", "").strip()
    )

    # —— Provider-specific fallback settings (used by ExploitAgent)
    ollama_base_url: str = field(
        default_factory=lambda: os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").strip()
    )
    ollama_model: str = field(
        default_factory=lambda: os.getenv("OLLAMA_MODEL", "llama3.1:8b").strip()
    )
    anthropic_api_key: str = field(
        default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", "").strip()
    )
    anthropic_model: str = field(
        default_factory=lambda: os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20240620").strip()
    )
    xai_api_key: str = field(
        default_factory=lambda: os.getenv("XAI_API_KEY", "").strip()
    )
    xai_model: str = field(
        default_factory=lambda: os.getenv("XAI_MODEL", "grok-2-1212").strip()
    )


    # ── CVE / NVD
    nvd_api_key: str = field(default_factory=lambda: os.getenv("NVD_API_KEY", "").strip())

    # ── Execution limits
    max_agent_loops: int = field(
        default_factory=lambda: int(os.getenv("MAX_AGENT_LOOPS", "15"))
    )
    default_timeout: int = field(
        default_factory=lambda: int(os.getenv("DEFAULT_TIMEOUT", "180"))
    )

    # ── SQLite state DB path
    # Hardcoded to a stable home-directory path so the DB is always found
    # regardless of CWD, enabling 100% reliable 4-day unattended runs.
    db_path: str = field(
        default_factory=lambda: os.path.abspath(
            os.getenv("DB_PATH", os.path.expanduser("~/GhillieSuite-EX/ghilliesuite_state.db"))
        )
    )

    # ── Tools that ALWAYS require Human-in-the-Loop confirmation
    hitl_tools: frozenset[str] = field(
        default_factory=lambda: frozenset({"sqlmap", "dalfox"})
    )

    # ── Nuclei severities that also trigger HitL
    nuclei_hitl_severities: frozenset[str] = field(
        default_factory=lambda: frozenset({"critical"})
    )

    # ── Authenticated scanning — set at runtime by the CLI (not from .env)
    # These are intentionally not loaded from environment variables because
    # session cookies/tokens change per engagement and should never be stored
    # persistently in .env files.
    auth_cookie: str = ""
    """Value of --cookie CLI flag. e.g. 'session=abc123; csrf=xyz'"""

    auth_header: str = ""
    """Value of --header CLI flag. e.g. 'Authorization: Bearer eyJ...' """

    @property
    def auth_headers_flags(self) -> list[str]:
        """
        Build the flat -H flag list consumed by build_command(auth_headers=...).
        Returns an empty list when no auth has been configured.

        Example output when both are set:
          ["-H", "Cookie: session=abc", "-H", "Authorization: Bearer xyz"]
        """
        flags: list[str] = []
        if self.auth_cookie:
            flags += ["-H", f"Cookie: {self.auth_cookie}"]
        if self.auth_header:
            flags += ["-H", self.auth_header]
        return flags

    @property
    def is_authenticated(self) -> bool:
        """True when any auth credential has been configured."""
        return bool(self.auth_cookie or self.auth_header)

    # ── Automation — set at runtime by the CLI --force-auto flag
    force_auto: bool = False
    """
    If True, all hitl_prompt() calls are silently approved.
    USE WITH EXTREME CAUTION — only on pre-authorised targets.
    Ideal for CI/CD pipelines and scheduled automated scans.
    """

    # ── Stealth mode — set at runtime by the CLI --stealth flag
    stealth_mode: bool = False
    """
    If True, apply conservative per-tool rate limiting to reduce WAF 429s.
    Injected into nuclei/sqlmap/ffuf/dirb command lines by build_command().
    """
    # ── Disable stealth override — set at runtime by the CLI --disable-stealth flag
    disable_stealth: bool = False
    """
    If True, ignore Commander/WAF stealth signals and run full execution.
    This overrides any auto-stealth detection for lab or WAF stress testing.
    """
    def __post_init__(self) -> None:
        """Run auto-detection immediately after the dataclass is initialised."""
        self.ai_provider, self.active_api_key = detect_ai_provider()

    @property
    def provider_display(self) -> str:
        """Human-readable provider label for log messages."""
        labels = {
            "openai": "OpenAI (gpt-4o-mini)",
            "gemini": "Google Gemini (gemini-2.5-pro)",
            "none": "None — no API key found",
        }
        return labels.get(self.ai_provider, self.ai_provider)

    @property
    def openai_model(self) -> str:
        return "gpt-4o-mini"

    @property
    def gemini_model(self) -> str:
        return "gemini-2.5-pro"


# ── Global singleton ────────────────────────────────────────────────────────────
cfg = Config()


# ── Validation ─────────────────────────────────────────────────────────────────
def validate_config(ai_provider: str | None = None) -> str:
    """
    Validate that a usable AI provider was detected.

    Args:
        ai_provider: Optional override. If None, uses the auto-detected provider.
                     Pass a value only when the user explicitly supplies --ai-provider.

    Returns:
        The resolved provider name ('openai' or 'gemini') to use for this run.

    Raises:
        RuntimeError: If no valid API key is available for the resolved provider.
    """
    resolved = ai_provider or cfg.ai_provider

    if resolved == "none" or not cfg.active_api_key:
        raise RuntimeError(
            "No AI provider API key found.\n\n"
            "Add ONE of the following to your .env file:\n"
            "  OPENAI_API_KEY=sk-...          # for OpenAI (auto-detected)\n"
            "  GEMINI_API_KEY=AIza...         # for Google Gemini (auto-detected)\n\n"
            "Get a Gemini key free at: https://aistudio.google.com/app/apikey\n"
            "Get an OpenAI key at:     https://platform.openai.com/api-keys"
        )

    # Warn if key doesn't match the expected prefix (manual override fallback)
    if resolved == "openai" and cfg.openai_api_key and not cfg.openai_api_key.startswith(_OPENAI_PREFIX):
        import warnings
        warnings.warn(
            f"OPENAI_API_KEY does not start with '{_OPENAI_PREFIX}'. "
            "Proceeding anyway — verify the key is correct.",
            stacklevel=2,
        )

    if resolved == "gemini" and cfg.gemini_api_key and not cfg.gemini_api_key.startswith(_GEMINI_PREFIX):
        import warnings
        warnings.warn(
            f"GEMINI_API_KEY does not start with '{_GEMINI_PREFIX}'. "
            "Proceeding anyway — verify the key is correct.",
            stacklevel=2,
        )

    return resolved
