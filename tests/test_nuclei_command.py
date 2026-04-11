import unittest

from ghilliesuite_ex.arsenal import build_command


class TestNucleiCommandConstruction(unittest.TestCase):
    def test_nuclei_command_does_not_force_custom_template_path(self) -> None:
        cmd = build_command("nuclei", "https://example.com")

        self.assertIn("-tags", cmd)
        self.assertNotIn("-t", cmd)


if __name__ == "__main__":
    unittest.main()
