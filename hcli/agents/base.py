"""
hcli/agents/base.py
───────────────────
Abstract base class shared by all agents (Supervisor, Recon, Exploit, Reporter).

Every Agent receives:
  • db       — shared StateDB for reading/writing structured state
  • ai       — the configured AI client (Gemini or OpenAI)  
  • scope    — list[str] of in-scope domains
  • console  — Rich Console for terminal output
  • config   — global Config object

Agents communicate through the DB — they never pass raw strings to each other.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from rich.console import Console

from hcli.config import Config, cfg
from hcli.state.db import StateDB


@dataclass
class AgentTask:
    """Input given to an agent when dispatched by the Supervisor."""

    target: str                   # Primary target domain or URL
    tool_name: str | None = None  # Specific tool override (None = agent decides)
    extra_args: list[str] = field(default_factory=list)
    reason: str = ""              # AI's stated reason for this task (for HitL display)
    safe_mode: bool = False       # If True: HitL on ALL tools, not just exploitation ones


@dataclass
class AgentResult:
    """Value returned by an agent after completing its task."""

    agent: str                    # Agent class name
    status: str                   # "ok" | "error" | "skipped"
    summary: str                  # One-line human-readable summary
    items_added: int = 0          # How many DB records were inserted
    error: str = ""               # Error message if status == "error"


class BaseAgent(ABC):
    """
    Abstract base for all agents.

    Subclasses must implement ``run(task: AgentTask) -> AgentResult``.
    All shared infrastructure (DB, AI client, console) is available as instance attrs.
    """

    def __init__(
        self,
        db: StateDB,
        ai_client,          # google.generativeai.GenerativeModel or openai.AsyncOpenAI
        scope: list[str],
        console: Console,
        config: Config | None = None,
    ) -> None:
        self.db = db
        self.ai = ai_client
        self.scope = scope
        self.console = console
        self.cfg = config or cfg

    @property
    def name(self) -> str:
        return self.__class__.__name__

    @abstractmethod
    async def run(self, task: AgentTask) -> AgentResult:
        """Execute the agent's specialised task and return a result."""

    async def _ask_ai(self, prompt: str, system: str = "") -> str:
        """
        Send a prompt to the AI model and return the response text.
        Handles both Gemini (google-generativeai) and a minimal OpenAI shim.
        Returns an empty string on failure (caller must handle gracefully).
        """
        try:
            # Gemini path
            if hasattr(self.ai, "generate_content"):
                full_prompt = f"{system}\n\n{prompt}" if system else prompt
                response = await _run_in_thread(self.ai.generate_content, full_prompt)
                return response.text or ""

            # OpenAI-compatible path (AsyncOpenAI)
            if hasattr(self.ai, "chat"):
                messages = []
                if system:
                    messages.append({"role": "system", "content": system})
                messages.append({"role": "user", "content": prompt})
                response = await self.ai.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=messages,
                    temperature=0.2,
                )
                return response.choices[0].message.content or ""

        except Exception as exc:
            self.console.print(f"[red]AI error in {self.name}: {exc}[/red]")

        return ""


async def _run_in_thread(fn, *args, **kwargs):
    """
    Run a synchronous function in a thread pool so it doesn't block the event loop.
    Needed for the synchronous google-generativeai SDK.
    """
    import asyncio
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: fn(*args, **kwargs))
