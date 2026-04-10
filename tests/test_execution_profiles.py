import io
import unittest

from rich.console import Console

from ghilliesuite_ex.agents.base import AgentTask
from ghilliesuite_ex.agents.exploit import ExploitAgent
from ghilliesuite_ex.config import Config, normalize_execution_profile
from ghilliesuite_ex.state.db import StateDB
from ghilliesuite_ex.state.models import Endpoint, Host


class _RecordingExploitAgent(ExploitAgent):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.calls: list[str] = []

    async def _select_recon_endpoints(self, limit: int = 200):
        return [Endpoint(url="https://example.com/search?q=1", params="q", source_tool="katana")]

    async def _fetch_sample_http_context(self, url: str):
        return {}

    async def _build_execution_plan(self, recon_urls, target, sample_context):
        return {
            "stealth_mode": False,
            "targets": [
                {
                    "url": "https://example.com/search?q=1",
                    "vectors": ["sqli", "xss", "ssrf", "idor", "graphql", "misconfig", "exposure"],
                    "confidence": 95,
                    "reason": "test plan",
                }
            ],
        }

    def _normalize_plan_targets(self, plan, endpoints):
        endpoint = Endpoint(url="https://example.com/search?q=1", params="q", source_tool="katana")
        return {
            endpoint.url: {
                "endpoint": endpoint,
                "vectors": {"sqli", "xss", "ssrf", "idor", "graphql", "misconfig", "exposure"},
                "confidence": 95,
            }
        }

    async def _run_sqlmap(self, *args, **kwargs):
        self.calls.append("sqlmap")
        return 1

    async def _run_dalfox(self, *args, **kwargs):
        self.calls.append("dalfox")
        return 1

    async def _run_nuclei(self, *args, **kwargs):
        self.calls.append("nuclei")
        return 1

    async def _run_nuclei_cves(self, *args, **kwargs):
        self.calls.append("nuclei_cves")
        return 1

    async def _check_bola_idor(self, *args, **kwargs):
        self.calls.append("bola")
        return 1

    async def analyze_idor(self, *args, **kwargs):
        self.calls.append("idor")
        return 1

    async def _check_graphql(self, *args, **kwargs):
        self.calls.append("graphql")
        return 1

    async def _check_cloud_ssrf(self, *args, **kwargs):
        self.calls.append("cloud_ssrf")
        return 1

    async def _run_ffuf_stage(self, *args, **kwargs):
        self.calls.append("ffuf_dir")
        if self._profile_allows_broad_fuzzing():
            self.calls.append("ffuf_ssrf")
        return 1

    async def _check_js_secrets(self, *args, **kwargs):
        self.calls.append("js_secret")
        return 1

    async def _check_prototype_pollution(self, *args, **kwargs):
        self.calls.append("proto")
        return 1

    async def _check_rsc_leak(self, *args, **kwargs):
        self.calls.append("rsc")
        return 1

    async def _run_trufflehog(self, *args, **kwargs):
        self.calls.append("trufflehog")
        return 1

    async def _check_js_deep_inspection(self, *args, **kwargs):
        self.calls.append("js_deep")
        return 1

    async def _check_ai_prompt_injection(self, *args, **kwargs):
        self.calls.append("ai_prompt")
        return 1


class TestExecutionProfiles(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.console = Console(file=io.StringIO(), force_terminal=False, color_system=None)

    async def _run_agent(self, profile: str, *, waf_evasion: bool = False, force_exploit: bool = False):
        config = Config()
        config.set_execution_profile(profile)
        config.waf_evasion = waf_evasion
        config.force_exploit = force_exploit

        async with StateDB(":memory:", target="example.com") as db:
            await db.insert_host(Host(domain="example.com", status_code=200, tech_stack="nginx"))
            await db.insert_endpoint(Endpoint(url="https://example.com/search?q=1", params="q", source_tool="katana"))
            agent = _RecordingExploitAgent(
                db=db,
                ai_client=None,
                scope=["example.com"],
                console=self.console,
                config=config,
            )
            result = await agent.run(AgentTask(target="example.com"))
        return result, agent.calls

    async def test_vdp_safe_runs_low_noise_checks_only(self) -> None:
        result, calls = await self._run_agent("vdp-safe")

        self.assertIn("js_secret", calls)
        self.assertIn("proto", calls)
        self.assertIn("js_deep", calls)
        self.assertIn("ai_prompt", calls)
        self.assertNotIn("sqlmap", calls)
        self.assertNotIn("dalfox", calls)
        self.assertNotIn("nuclei", calls)
        self.assertNotIn("ffuf_dir", calls)
        self.assertNotIn("ffuf_ssrf", calls)
        self.assertNotIn("rsc", calls)
        self.assertNotIn("trufflehog", calls)
        self.assertIn("vdp-safe", result.summary)

    async def test_balanced_runs_targeted_checks_without_broad_fuzzing(self) -> None:
        _, calls = await self._run_agent("balanced", waf_evasion=True, force_exploit=False)

        self.assertIn("sqlmap", calls)
        self.assertIn("dalfox", calls)
        self.assertIn("nuclei", calls)
        self.assertIn("graphql", calls)
        self.assertIn("cloud_ssrf", calls)
        self.assertIn("ffuf_dir", calls)
        self.assertIn("rsc", calls)
        self.assertIn("trufflehog", calls)
        self.assertNotIn("ffuf_ssrf", calls)

    async def test_aggressive_enables_broad_fuzzing_paths(self) -> None:
        _, calls = await self._run_agent("aggressive", waf_evasion=True, force_exploit=False)

        self.assertIn("sqlmap", calls)
        self.assertIn("dalfox", calls)
        self.assertIn("nuclei", calls)
        self.assertIn("ffuf_dir", calls)
        self.assertIn("ffuf_ssrf", calls)


class TestExecutionProfileValidation(unittest.TestCase):
    def test_normalize_execution_profile_accepts_valid_values(self) -> None:
        self.assertEqual(normalize_execution_profile("VDP-SAFE"), "vdp-safe")
        self.assertEqual(normalize_execution_profile("balanced"), "balanced")
        self.assertEqual(normalize_execution_profile("aggressive"), "aggressive")

    def test_normalize_execution_profile_rejects_invalid_values(self) -> None:
        with self.assertRaises(ValueError):
            normalize_execution_profile("turbo-chaos")


if __name__ == "__main__":
    unittest.main()
