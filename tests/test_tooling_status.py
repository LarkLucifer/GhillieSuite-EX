import unittest
from unittest.mock import patch

from ghilliesuite_ex.arsenal import collect_tooling_status


class TestToolingStatus(unittest.TestCase):
    @patch("ghilliesuite_ex.arsenal.importlib.util.find_spec")
    @patch("ghilliesuite_ex.arsenal.shutil.which")
    def test_vdp_safe_marks_disabled_tools_and_optional_dependency(
        self,
        mock_which,
        mock_find_spec,
    ) -> None:
        installed = {"subfinder", "katana", "httpx"}
        mock_which.side_effect = lambda binary: f"/usr/bin/{binary}" if binary in installed else None
        mock_find_spec.return_value = None

        status = collect_tooling_status(profile="vdp-safe")

        self.assertEqual(status.profile, "vdp-safe")
        self.assertEqual(status.required_tools, ("subfinder", "katana", "httpx"))
        self.assertIn("nuclei", status.disabled_by_profile)
        self.assertIn("ffuf", status.disabled_by_profile)
        self.assertTrue(all(dep.name != "" for dep in status.optional_dependencies))
        self.assertFalse(any(dep.installed for dep in status.optional_dependencies))

    @patch("ghilliesuite_ex.arsenal.importlib.util.find_spec")
    @patch("ghilliesuite_ex.arsenal.shutil.which")
    def test_balanced_keeps_ffuf_optional_and_playwright_installed(
        self,
        mock_which,
        mock_find_spec,
    ) -> None:
        mock_which.side_effect = lambda binary: f"/usr/bin/{binary}"
        mock_find_spec.return_value = object()

        status = collect_tooling_status(profile="balanced")

        self.assertEqual(status.profile, "balanced")
        self.assertIn("ffuf", status.optional_tools)
        self.assertNotIn("ffuf", status.disabled_by_profile)
        self.assertIn("nuclei", status.required_tools)
        self.assertTrue(all(dep.installed for dep in status.optional_dependencies))


if __name__ == "__main__":
    unittest.main()
