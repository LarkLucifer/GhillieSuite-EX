import unittest
from unittest.mock import patch

from typer.testing import CliRunner

from ghilliesuite_ex import __version__
from ghilliesuite_ex.main import app


class TestCliSmoke(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = CliRunner()

    def test_help_renders(self) -> None:
        result = self.runner.invoke(app, ["--help"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("GhillieSuite-EX.sec", result.stdout)
        self.assertIn("check-tools", result.stdout)

    def test_version_renders(self) -> None:
        result = self.runner.invoke(app, ["version"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn(__version__, result.stdout)

    def test_check_tools_runs(self) -> None:
        result = self.runner.invoke(app, ["check-tools"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Required Tools", result.stdout)

    def test_check_config_reports_missing_key(self) -> None:
        result = self.runner.invoke(app, ["check-config"])
        self.assertEqual(result.exit_code, 1)
        self.assertIn("Configuration error:", result.stdout)

    def test_check_config_accepts_mocked_provider(self) -> None:
        with patch("ghilliesuite_ex.main.validate_config", return_value="openai"):
            result = self.runner.invoke(app, ["check-config"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Configuration valid.", result.stdout)
