"""
ghilliesuite_ex/utils/executor.py
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
  • run_tool_to_file() runs binaries that write their output directly to disk
    (subfinder -o, httpx -json -o, ffuf -of json -o) for reliable inter-tool
    data handoff without brittle stdin piping.
  • WAF Cooldown: sleep is performed OUTSIDE the lock so concurrent tools are
    never blocked waiting on the lock itself.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path


_EVASION_COOLDOWN_SECONDS = 60
_last_waf_block_time = 0.0
_cooldown_lock = asyncio.Lock()


MAX_OUTPUT_BYTES = 512 * 1024  # 512 KB cap on raw stdout


@dataclass
class ToolResult:
    """Return value from run_tool() and run_tool_to_file()."""

    stdout: str
    stderr: str
    returncode: int
    error: str = ""          # populated on exceptions (timeout, missing binary, etc.)
    output_file: Path | None = field(default=None)  # set by run_tool_to_file()

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
    global _last_waf_block_time

    # Global Evasion Cooldown Check — sleep OUTSIDE lock to avoid blocking other tools
    wait_needed = 0.0
    async with _cooldown_lock:
        now = time.time()
        elapsed = now - _last_waf_block_time
        if elapsed < _EVASION_COOLDOWN_SECONDS:
            wait_needed = _EVASION_COOLDOWN_SECONDS - elapsed
    if wait_needed > 0:
        await asyncio.sleep(wait_needed)

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

        res = ToolResult(
            stdout=stdout_text,
            stderr=stderr_text,
            returncode=proc.returncode or 0,
        )

        # Detect WAF Blocks (403/429)
        combined = (stdout_text + stderr_text).lower()
        if "403 forbidden" in combined or "429 too many requests" in combined:
            async with _cooldown_lock:
                _last_waf_block_time = time.time()

        return res

    except FileNotFoundError:
        binary = cmd[0]
        return ToolResult(
            stdout="",
            stderr="",
            returncode=127,
            error=(
                f"❌  Binary '{binary}' not found on PATH. "
                f"Install it and ensure it is accessible. "
                f"Run 'GhillieSuite-EX.sec check-tools' to see all missing binaries."
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


async def run_tool_to_file(
    cmd: list[str],
    output_path: Path,
    timeout: int = 180,
) -> ToolResult:
    """
    Execute an external binary that writes its results directly to a file.

    This is the preferred execution method for recon tools that support an
    output file flag (e.g. subfinder -o, httpx -json -o, ffuf -of json -o,
    katana -j -o).
    File-based I/O completely eliminates the brittle stdin-piping approach and
    ensures zero data loss regardless of stdout buffering behaviour.

    Args:
        cmd:         Full command list. The caller is responsible for including
                     the output file flag (e.g. ['-o', str(output_path)]).
        output_path: Expected output file path. Used to verify the tool wrote
                     something and to populate ToolResult.output_file.
        timeout:     Seconds before the process is forcibly killed.

    Returns:
        ToolResult where .output_file is set to output_path if it exists after
        execution, otherwise None. .stdout will contain any progress text the
        tool wrote to stdout (usually empty for -silent tools).
    """
    global _last_waf_block_time

    # Ensure parent directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Global Evasion Cooldown Check — sleep OUTSIDE lock to avoid blocking other tools
    wait_needed = 0.0
    async with _cooldown_lock:
        now = time.time()
        elapsed = now - _last_waf_block_time
        if elapsed < _EVASION_COOLDOWN_SECONDS:
            wait_needed = _EVASION_COOLDOWN_SECONDS - elapsed
    if wait_needed > 0:
        await asyncio.sleep(wait_needed)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout_raw, stderr_raw = await asyncio.wait_for(
                proc.communicate(),
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

        stdout_text = stdout_raw[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
        stderr_text = stderr_raw[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")

        # Verify that the tool actually wrote the output file
        resolved_output = output_path if output_path.exists() and output_path.stat().st_size > 0 else None

        res = ToolResult(
            stdout=stdout_text,
            stderr=stderr_text,
            returncode=proc.returncode or 0,
            output_file=resolved_output,
        )

        # Detect WAF Blocks (403/429)
        combined = (stdout_text + stderr_text).lower()
        if "403 forbidden" in combined or "429 too many requests" in combined:
            async with _cooldown_lock:
                _last_waf_block_time = time.time()

        return res

    except FileNotFoundError:
        binary = cmd[0]
        return ToolResult(
            stdout="",
            stderr="",
            returncode=127,
            error=(
                f"❌  Binary '{binary}' not found on PATH. "
                f"Install it and ensure it is accessible. "
                f"Run 'GhillieSuite-EX.sec check-tools' to see all missing binaries."
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
