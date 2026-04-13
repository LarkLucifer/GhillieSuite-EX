import io
import json
import shutil
import unittest
import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from rich.console import Console

from ghilliesuite_ex.agents.base import AgentResult, AgentTask, BaseAgent
from ghilliesuite_ex.agents.exploit import ExploitAgent
from ghilliesuite_ex.agents.recon import _probe_url
from ghilliesuite_ex.agents.reporter import ReporterAgent
from ghilliesuite_ex.config import Config
from ghilliesuite_ex.state.db import StateDB
from ghilliesuite_ex.state.models import Endpoint, Finding, Host
from ghilliesuite_ex.utils.redaction import redact_text
from ghilliesuite_ex.utils.scope import load_scope


class _DummyAgent(BaseAgent):
    async def run(self, task: AgentTask) -> AgentResult:
        return AgentResult(agent=self.name, status="ok", summary="noop")


class _FailingAI:
    def generate_content(self, prompt: str):
        raise TimeoutError("simulated timeout")


class _AuthAwareExploitAgent(ExploitAgent):
    async def _ai_triage(self, finding, status_code, content_type, response_body):
        return {
            "is_vulnerable": True,
            "is_lead": False,
            "confidence": 95,
            "technical_reasoning": "Replay validation preserved the original authenticated context.",
        }

    async def _generate_poc(self, finding, triage_reason):
        return ""


class _RecordingAsyncClient:
    last_init_kwargs = None
    last_get_url = None
    last_get_kwargs = None

    def __init__(self, **kwargs):
        type(self).last_init_kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, **kwargs):
        type(self).last_get_url = url
        type(self).last_get_kwargs = kwargs
        return SimpleNamespace(
            url=url,
            status_code=200,
            headers={"Content-Type": "text/html; charset=utf-8"},
            text="<html>ok</html>",
            elapsed=SimpleNamespace(total_seconds=lambda: 0.12),
        )


class TestRedaction(unittest.TestCase):
    def test_redact_sensitive_headers_and_tokens(self) -> None:
        raw = (
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret.signature\n"
            "Cookie: sessionid=supersecret; csrftoken=anothersecret\n"
            "X-API-Key: topsecretapikey1234567890\n"
            "GET /api?api_key=querysecret123456&token=othertoken999 HTTP/1.1\n"
            "openai_key=sk-abcdefghijklmnopQRSTUV1234567890\n"
            "github=ghp_abcdefghijklmnopqrstuvwxyz1234567890\n"
        )
        redacted = redact_text(raw)

        self.assertIn("Authorization: [REDACTED]", redacted)
        self.assertIn("Cookie: [REDACTED]", redacted)
        self.assertIn("X-API-Key: [REDACTED]", redacted)
        self.assertIn("[REDACTED_SECRET]", redacted)

        self.assertNotIn("sessionid=supersecret", redacted)
        self.assertNotIn("querysecret123456", redacted)
        self.assertNotIn("sk-abcdefghijklmnopQRSTUV1234567890", redacted)
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz1234567890", redacted)


class TestAIFallback(unittest.IsolatedAsyncioTestCase):
    async def test_base_agent_disables_ai_after_timeout(self) -> None:
        config = Config()
        config.enable_ai()
        config.ai_retries = 1
        console = Console(file=io.StringIO(), force_terminal=False, color_system=None)

        async with StateDB(":memory:", target="example.com") as db:
            agent = _DummyAgent(
                db=db,
                ai_client=_FailingAI(),
                scope=["example.com"],
                console=console,
                config=config,
            )
            result = await agent._ask_ai("hello")

        self.assertEqual(result, "")
        self.assertFalse(config.ai_enabled)
        self.assertIn("simulated timeout", config.ai_disabled_reason.lower())


class TestExploitValidationAuthAware(unittest.IsolatedAsyncioTestCase):
    async def test_validate_and_insert_finding_reuses_auth_headers_cookie_and_proxy(self) -> None:
        config = Config()
        config.disable_ai("No API key configured.")
        config.auth_cookie = "sessionid=abc123; csrftoken=xyz"
        config.auth_header = "Authorization: Bearer token123"
        config.proxy = "http://127.0.0.1:8080"
        console = Console(file=io.StringIO(), force_terminal=False, color_system=None)

        finding = Finding(
            tool="nuclei",
            target="https://example.com/dashboard",
            severity="medium",
            title="Sensitive Dashboard Exposure",
            evidence="Dashboard returned to the scanner.",
            reproducible_steps="1. Request the dashboard path.",
            raw_output="",
        )

        async with StateDB(":memory:", target="example.com") as db:
            agent = _AuthAwareExploitAgent(
                db=db,
                ai_client=None,
                scope=["example.com"],
                console=console,
                config=config,
            )

            with patch("httpx.AsyncClient", _RecordingAsyncClient):
                stored = await agent._validate_and_insert_finding(finding)

            self.assertTrue(stored)
            self.assertEqual(_RecordingAsyncClient.last_get_url, finding.target)
            self.assertEqual(_RecordingAsyncClient.last_get_kwargs, {})

            init_kwargs = dict(_RecordingAsyncClient.last_init_kwargs or {})
            self.assertEqual(init_kwargs.get("proxy"), "http://127.0.0.1:8080")
            self.assertEqual(init_kwargs.get("timeout"), 5.0)
            self.assertTrue(init_kwargs.get("follow_redirects"))

            headers = dict(init_kwargs.get("headers") or {})
            self.assertEqual(headers.get("Authorization"), "Bearer token123")
            self.assertEqual(headers.get("Cookie"), "sessionid=abc123; csrftoken=xyz")
            self.assertIn("Mozilla/5.0", headers.get("User-Agent", ""))

            findings = await db.get_findings()
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].target, finding.target)


class TestReporterSafety(unittest.IsolatedAsyncioTestCase):
    async def test_reports_redact_secrets_and_mark_ai_disabled(self) -> None:
        console = Console(file=io.StringIO(), force_terminal=False, color_system=None)
        tmp_path = Path("tmp") / f"reporter_safety_{uuid4().hex}"
        tmp_path.mkdir(parents=True, exist_ok=True)
        try:
            evidence_dir = tmp_path / "evidence"
            output_dir = tmp_path / "reports"
            evidence_dir.mkdir(parents=True, exist_ok=True)
            output_dir.mkdir(parents=True, exist_ok=True)

            req_path = evidence_dir / "captured.request.txt"
            res_path = evidence_dir / "captured.response.txt"
            req_path.write_text(
                "GET /api?api_key=querysecret123456 HTTP/1.1\n"
                "Authorization: Bearer bearersecret123456789\n"
                "Cookie: sessionid=supersecret\n",
                encoding="utf-8",
            )
            res_path.write_text(
                "HTTP/1.1 200 OK\n"
                "Set-Cookie: sessionid=serversecret\n\n"
                "{\"token\":\"ghp_abcdefghijklmnopqrstuvwxyz1234567890\"}",
                encoding="utf-8",
            )

            config = Config()
            config.disable_ai("No API key configured.")
            config.output_dir = str(output_dir)
            config.evidence_dir = str(evidence_dir)

            async with StateDB(":memory:", target="example.com") as db:
                await db.insert_host(Host(domain="example.com", status_code=200, tech_stack="nginx"))
                await db.insert_endpoint(Endpoint(url="https://example.com/api?api_key=querysecret123456"))
                await db.insert_finding(
                    Finding(
                        tool="sqlmap",
                        target="https://example.com/api",
                        severity="high",
                        title="SQL Injection",
                        evidence=(
                            f"Evidence Request: {req_path}\n"
                            f"Evidence Response: {res_path}\n"
                            "Authorization: Bearer bearersecret123456789"
                        ),
                        reproducible_steps="Use Cookie: sessionid=supersecret",
                        raw_output="openai=sk-abcdefghijklmnopQRSTUV1234567890",
                    )
                )

                reporter = ReporterAgent(
                    db=db,
                    ai_client=None,
                    scope=["example.com"],
                    console=console,
                    config=config,
                )
                await reporter.run(AgentTask(target="example.com"))

            report_files = list(output_dir.glob("*.*"))
            self.assertTrue(any(path.suffix == ".json" for path in report_files))
            self.assertTrue(any(path.suffix == ".md" for path in report_files))
            self.assertTrue(any(path.suffix == ".html" for path in report_files))

            for path in report_files:
                content = path.read_text(encoding="utf-8", errors="replace")
                self.assertIn("AI triage disabled", content)
                self.assertNotIn("sessionid=supersecret", content)
                self.assertNotIn("querysecret123456", content)
                self.assertNotIn("bearersecret123456789", content)
                self.assertNotIn("sk-abcdefghijklmnopQRSTUV1234567890", content)
                self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz1234567890", content)
        finally:
            shutil.rmtree(tmp_path, ignore_errors=True)

    async def test_reports_serialize_scope_spec_in_json(self) -> None:
        console = Console(file=io.StringIO(), force_terminal=False, color_system=None)
        tmp_path = Path("tmp") / f"reporter_scope_{uuid4().hex}"
        tmp_path.mkdir(parents=True, exist_ok=True)
        try:
            config = Config()
            config.disable_ai("No API key configured.")
            config.output_dir = str(tmp_path)
            scope = load_scope("example.com,exclude:admin.example.com")

            async with StateDB(":memory:", target="example.com") as db:
                await db.insert_host(Host(domain="example.com", status_code=200, tech_stack="nginx"))
                reporter = ReporterAgent(
                    db=db,
                    ai_client=None,
                    scope=scope,
                    console=console,
                    config=config,
                )
                await reporter.run(AgentTask(target="example.com"))

            json_report = next(tmp_path.glob("*.json"))
            report_data = json.loads(json_report.read_text(encoding="utf-8"))
            self.assertEqual(report_data["scope"]["entries"], ["example.com", "exclude:admin.example.com"])
            self.assertEqual(report_data["scope"]["rules"][0]["kind"], "host_exact")
            self.assertEqual(report_data["scope"]["rules"][1]["include"], False)
        finally:
            shutil.rmtree(tmp_path, ignore_errors=True)


class _FakeResponse:
    def __init__(self, url: str) -> None:
        self.url = url
        self.status_code = 200
        self.headers = {"server": "nginx", "x-powered-by": "php"}


class _AwaitedCurlSession:
    impersonate = "chrome120"

    async def get(self, url: str, **kwargs):
        return _FakeResponse(url)


class TestAsyncHttpProbe(unittest.IsolatedAsyncioTestCase):
    async def test_probe_url_awaits_async_curl_session_response(self) -> None:
        result = await _probe_url(
            _AwaitedCurlSession(),
            "https://example.com",
            asyncio.Semaphore(1),
        )

        self.assertIsNotNone(result)
        self.assertEqual(result["url"], "https://example.com")
        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["server"], "nginx")
        self.assertEqual(result["tech_stack"], "nginx,php")
