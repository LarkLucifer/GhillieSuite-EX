import unittest

from ghilliesuite_ex.agents.recon_pipeline import (
    build_httpx_targets,
    build_katana_candidates,
    select_arjun_targets,
    select_katana_targets,
)


class TestReconPipelineHelpers(unittest.TestCase):
    def test_build_httpx_targets_filters_scope_and_deduplicates(self) -> None:
        targets = build_httpx_targets(
            ["example.com", "example.com", "outside.com"],
            ["example.com"],
        )

        self.assertEqual(
            targets,
            ["http://example.com", "https://example.com"],
        )

    def test_build_katana_candidates_normalizes_to_origin(self) -> None:
        candidates = build_katana_candidates(
            [
                "https://example.com/path?a=1",
                "https://example.com/other",
                "http://api.example.com/v1/users",
                "not-a-url",
            ]
        )

        self.assertEqual(
            candidates,
            ["https://example.com", "http://api.example.com"],
        )

    def test_select_katana_targets_respects_recrawl_interval(self) -> None:
        selected = select_katana_targets(
            ["https://example.com", "https://api.example.com", "https://stale.example.com"],
            history={"https://api.example.com", "https://stale.example.com"},
            last_crawl_run={
                "https://api.example.com": 4,
                "https://stale.example.com": 1,
            },
            recon_run_count=5,
            recrawl_interval=3,
            max_targets=10,
        )

        self.assertEqual(
            selected,
            ["https://example.com", "https://stale.example.com"],
        )

    def test_select_arjun_targets_prioritizes_api_and_deduplicates_base_paths(self) -> None:
        selected = select_arjun_targets(
            [
                "https://example.com/blog/",
                "https://example.com/api/users",
                "https://example.com/api/users/1234567890123456789012345",
                "https://example.com/profile.php",
                "https://example.com/assets/app.js",
                "https://outside.com/api/users",
            ],
            history=set(),
            scope=["example.com"],
            limit=10,
        )

        self.assertEqual(
            selected,
            ["https://example.com/api/users", "https://example.com/profile.php"],
        )
