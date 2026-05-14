import unittest

from ghilliesuite_ex.safety import (
    get_execution_safety_policy,
    normalize_tool_label,
    should_prompt_for_tool,
)


class TestExecutionSafetyPolicy(unittest.TestCase):
    def test_vdp_safe_policy_disables_targeted_exploitation(self) -> None:
        policy = get_execution_safety_policy("vdp-safe")
        self.assertFalse(policy.targeted_exploitation_enabled)
        self.assertFalse(policy.broad_fuzzing_enabled)
        self.assertFalse(policy.ffuf_enabled)
        self.assertFalse(policy.force_exploit_allowed)

    def test_balanced_policy_enables_targeted_but_not_broad_fuzzing(self) -> None:
        policy = get_execution_safety_policy("balanced")
        self.assertTrue(policy.targeted_exploitation_enabled)
        self.assertFalse(policy.broad_fuzzing_enabled)
        self.assertTrue(policy.ffuf_enabled)
        self.assertFalse(policy.force_exploit_allowed)

    def test_aggressive_policy_enables_force_exploit(self) -> None:
        policy = get_execution_safety_policy("aggressive")
        self.assertTrue(policy.targeted_exploitation_enabled)
        self.assertTrue(policy.broad_fuzzing_enabled)
        self.assertTrue(policy.force_exploit_allowed)


class TestHitlPolicy(unittest.TestCase):
    def test_normalize_tool_label_strips_suffixes(self) -> None:
        self.assertEqual(normalize_tool_label("nuclei (critical)"), "nuclei")
        self.assertEqual(normalize_tool_label("ffuf (SSRF)"), "ffuf")

    def test_safe_mode_prompts_everything(self) -> None:
        self.assertTrue(
            should_prompt_for_tool(
                "nuclei",
                safe_mode=True,
                config_hitl_tools=frozenset(),
                registry_hitl_required=False,
            )
        )

    def test_ssrf_tool_prompts_even_without_registry_flag(self) -> None:
        self.assertTrue(
            should_prompt_for_tool(
                "ffuf (SSRF)",
                safe_mode=False,
                config_hitl_tools=frozenset(),
                registry_hitl_required=False,
            )
        )

    def test_hitl_registry_or_config_can_require_prompt(self) -> None:
        self.assertTrue(
            should_prompt_for_tool(
                "sqlmap",
                safe_mode=False,
                config_hitl_tools=frozenset({"sqlmap"}),
                registry_hitl_required=False,
            )
        )
        self.assertTrue(
            should_prompt_for_tool(
                "dalfox",
                safe_mode=False,
                config_hitl_tools=frozenset(),
                registry_hitl_required=True,
            )
        )
        self.assertFalse(
            should_prompt_for_tool(
                "nuclei",
                safe_mode=False,
                config_hitl_tools=frozenset(),
                registry_hitl_required=False,
            )
        )


if __name__ == "__main__":
    unittest.main()
