import unittest

from ghilliesuite_ex.config import Config, RuntimeConfigOverrides


class TestConfigRuntimeOverrides(unittest.TestCase):
    def test_apply_runtime_overrides_updates_runtime_fields(self) -> None:
        config = Config()

        config.apply_runtime_overrides(
            RuntimeConfigOverrides(
                execution_profile="aggressive",
                auth_cookie=" session=abc123 ",
                auth_header=" Authorization: Bearer token ",
                force_auto=True,
                enable_screenshots=True,
                max_agent_loops=42,
            )
        )

        self.assertEqual(config.execution_profile, "aggressive")
        self.assertEqual(config.auth_cookie, "session=abc123")
        self.assertEqual(config.auth_header, "Authorization: Bearer token")
        self.assertTrue(config.force_auto)
        self.assertTrue(config.enable_screenshots)
        self.assertEqual(config.max_agent_loops, 42)

    def test_apply_runtime_overrides_resets_previous_run_state(self) -> None:
        baseline = Config()
        config = Config()

        config.apply_runtime_overrides(
            RuntimeConfigOverrides(
                execution_profile="aggressive",
                auth_cookie="session=abc123",
                force_auto=True,
                max_agent_loops=42,
            )
        )
        config.apply_runtime_overrides(
            RuntimeConfigOverrides(
                execution_profile="balanced",
            )
        )

        self.assertEqual(config.execution_profile, "balanced")
        self.assertEqual(config.auth_cookie, baseline.auth_cookie)
        self.assertEqual(config.force_auto, baseline.force_auto)
        self.assertEqual(config.max_agent_loops, baseline.max_agent_loops)
