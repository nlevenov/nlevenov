from __future__ import annotations

from pathlib import Path

import pytest

from socprio.config import Settings

from helpers import BAD_HASH

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    feeds = tmp_path / "feeds"
    feeds.mkdir()
    (feeds / "test_feed.csv").write_text(
        "indicator,type,score,tags,description\n"
        "203.0.113.10,ip,85,c2;botnet,test c2\n"
        "203.0.113.64/28,ip,70,scanner,test range\n"
        "evil.test,domain,90,phishing,test domain\n"
        f"{BAD_HASH},sha256,95,malware,test hash\n",
        encoding="utf-8",
    )
    (feeds / "tor_exit_nodes.txt").write_text("# comment\n198.51.100.66\n", encoding="utf-8")

    result = Settings(
        database=str(tmp_path / "test.db"),
        model_path=str(tmp_path / "model.joblib"),
        rules_path=str(ROOT / "config" / "rules.yaml"),
        assets_path=str(ROOT / "config" / "assets.yaml"),
    )
    result.intel.feeds_dir = str(feeds)
    return result
