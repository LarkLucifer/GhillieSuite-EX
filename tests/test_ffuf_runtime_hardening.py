import io
import unittest
from unittest.mock import patch

from rich.console import Console

from ghilliesuite_ex.agents.exploit import ExploitAgent
from ghilliesuite_ex.config import Config


def _extract_headers(cmd: list[str]) -> list[str]:
    headers: list[str] = []
    idx = 0
    while idx < len(cmd):
        if cmd[idx] == "-H" and idx + 1 < len(cmd):
            headers.append(str(cmd[idx + 1]))
            idx += 2
            continue
        idx += 1
    return headers


class TestFfufRuntimeHardening(unittest.TestCase):
    def _make_agent(self, cfg: Config) -> ExploitAgent:
        return ExploitAgent(
            db=None,  # helper method tests do not touch DB
            ai_client=None,
            scope=["example.com"],
            console=Console(file=io.StringIO(), force_terminal=False, color_system=None),
            config=cfg,
        )

    @staticmethod
    def _option_value(cmd: list[str], option: str) -> str:
        idx = cmd.index(option)
        return cmd[idx + 1]

    def test_ffuf_hardening_adds_rate_jitter_random_ua_and_auth_headers(self) -> None:
        cfg = Config()
        cfg.auth_header = "Authorization: Bearer token123"
        agent = self._make_agent(cfg)
        cmd = ["ffuf", "-w", "wl.txt", "-u", "https://example.com/FUZZ", "-s"]

        with patch("ghilliesuite_ex.agents.exploit.random.choice", return_value="UA-TEST"):
            hardened = agent._apply_ffuf_runtime_hardening(
                cmd,
                include_auth_headers=True,
                include_proxy=False,
            )

        headers = _extract_headers(hardened)
        self.assertIn("Authorization: Bearer token123", headers)
        self.assertIn("User-Agent: UA-TEST", headers)
        self.assertEqual(self._option_value(hardened, "-rate"), "5")
        self.assertEqual(self._option_value(hardened, "-p"), "0.1-0.5")

    def test_user_supplied_user_agent_is_respected_without_random_override(self) -> None:
        cfg = Config()
        cfg.auth_header = "User-Agent: CustomAgent/9.9"
        agent = self._make_agent(cfg)
        cmd = ["ffuf", "-w", "wl.txt", "-u", "https://example.com/FUZZ", "-s"]

        with patch("ghilliesuite_ex.agents.exploit.random.choice", return_value="UA-TEST"):
            hardened = agent._apply_ffuf_runtime_hardening(
                cmd,
                include_auth_headers=True,
                include_proxy=False,
            )

        headers = _extract_headers(hardened)
        ua_headers = [h for h in headers if h.lower().startswith("user-agent:")]
        self.assertEqual(ua_headers, ["User-Agent: CustomAgent/9.9"])

    def test_proxy_is_injected_for_ffuf_commands(self) -> None:
        cfg = Config()
        cfg.proxy = "http://127.0.0.1:8080"
        agent = self._make_agent(cfg)
        cmd = ["ffuf", "-w", "wl.txt", "-u", "https://example.com/FUZZ", "-s"]

        hardened = agent._apply_ffuf_runtime_hardening(
            cmd,
            include_auth_headers=False,
            include_proxy=True,
        )

        self.assertIn("-x", hardened)
        self.assertEqual(self._option_value(hardened, "-x"), "http://127.0.0.1:8080")


if __name__ == "__main__":
    unittest.main()
