"""
hcli/utils/executor.py
──────────────────────
Async subprocess executor — the only place in the codebase where external
binaries are actually invoked.

Design decisions:
  • asyncio.create_subprocess_exec is used (not shell=True) to avoid shell
    injection and to cleanly handle stderr separately from stdout.
  • FileNotFoundError is caught and converted to a ToolResult with an
    informative error message so the agent loop never crashes on a missing binary.
  • A configurable timeout (seconds) terminates runaway processes.
  • stdout is capped at MAX_OUTPUT_BYTES to prevent memory issues on
    verbose tools like gau.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass


MAX_OUTPUT_BYTES = 512 * 1024  # 512 KB cap on raw stdout


@dataclass
class ToolResult:
    """Return value from run_tool()."""

    stdout: str
    stderr: str
    returncode: int
    error: str = ""          # populated on exceptions (timeout, missing binary, etc.)

    @property
    def ok(self) -> bool:
        """True if the tool ran without fatal errors."""
        return not self.error and self.returncode == 0

    def truncated_stdout(self, max_chars: int = 3000) -> str:
        """Return a truncated stdout string safe to display in Rich panels."""
        if len(self.stdout) <= max_chars:
            return self.stdout
        half = max_chars // 2
        return self.stdout[:half] + f"\n…[{len(self.stdout) - max_chars} chars omitted]…\n" + self.stdout[-half:]


async def run_tool(
    cmd: list[str],
    timeout: int = 180,
    stdin_data: str | None = None,
) -> ToolResult:
    """
    Execute an external binary asynchronously and return its output.

    Args:
        cmd:        Full command as a list of strings, e.g. ['subfinder', '-d', 'example.com']
        timeout:    Seconds before the process is forcibly killed. Default: 180.
        stdin_data: Optional text to pipe into the process's stdin (e.g. a host list for httpx).

    Returns:
        ToolResult with stdout, stderr, returncode, and an error string if applicable.
    """
    stdin_pipe = asyncio.subprocess.PIPE if stdin_data else None

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=stdin_pipe,
        )

        stdin_bytes = stdin_data.encode() if stdin_data else None

        try:
            stdout_raw, stderr_raw = await asyncio.wait_for(
                proc.communicate(input=stdin_bytes),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return ToolResult(
                stdout="",
                stderr="",
                returncode=-1,
                error=f"⏱  Tool '{cmd[0]}' timed out after {timeout}s and was killed.",
            )

        # Cap raw output to prevent memory exhaustion
        stdout_text = stdout_raw[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
        stderr_text = stderr_raw[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")

        return ToolResult(
            stdout=stdout_text,
            stderr=stderr_text,
            returncode=proc.returncode or 0,
        )

    except FileNotFoundError:
        binary = cmd[0]
        return ToolResult(
            stdout="",
            stderr="",
            returncode=127,
            error=(
                f"❌  Binary '{binary}' not found on PATH. "
                f"Install it and ensure it is accessible. "
                f"Run 'hcli.sec check-tools' to see all missing binaries."
            ),
        )

    except PermissionError:
        return ToolResult(
            stdout="", stderr="", returncode=126,
            error=f"🔒  Permission denied trying to execute '{cmd[0]}'.",
        )

    except Exception as exc:  # noqa: BLE001
        return ToolResult(
            stdout="", stderr="", returncode=-1,
            error=f"💥  Unexpected error running '{cmd[0]}': {exc}",
        )
