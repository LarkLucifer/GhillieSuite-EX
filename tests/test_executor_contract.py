import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ghilliesuite_ex.utils.executor import run_tool_to_file


class _FakeProcess:
    def __init__(self, *, stdout: bytes = b"", stderr: bytes = b"", returncode: int = 0, on_communicate=None):
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode
        self._on_communicate = on_communicate

    async def communicate(self):
        if self._on_communicate is not None:
            self._on_communicate()
        return self._stdout, self._stderr

    def kill(self):
        return None


class TestExecutorFileContract(unittest.IsolatedAsyncioTestCase):
    async def test_run_tool_to_file_drops_stale_output_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "stale.json"
            output_path.write_text('{"old": true}', encoding="utf-8")

            async def _fake_exec(*args, **kwargs):
                return _FakeProcess(returncode=0)

            with patch("ghilliesuite_ex.utils.executor.asyncio.create_subprocess_exec", _fake_exec):
                result = await run_tool_to_file(["fake-tool"], output_path, timeout=5)

            self.assertTrue(result.ok)
            self.assertIsNone(result.output_file)
            self.assertFalse(output_path.exists())

    async def test_run_tool_to_file_returns_fresh_output_path_when_written(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "fresh.json"

            def _write_output() -> None:
                output_path.write_text('{"ok": true}', encoding="utf-8")

            async def _fake_exec(*args, **kwargs):
                return _FakeProcess(returncode=0, on_communicate=_write_output)

            with patch("ghilliesuite_ex.utils.executor.asyncio.create_subprocess_exec", _fake_exec):
                result = await run_tool_to_file(["fake-tool"], output_path, timeout=5)

            self.assertTrue(result.ok)
            self.assertEqual(result.output_file, output_path.resolve())
