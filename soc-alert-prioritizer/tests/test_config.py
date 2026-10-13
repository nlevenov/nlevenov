import pytest

from socprio.config import load_settings


def test_defaults_when_no_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SOCPRIO_CONFIG", raising=False)
    settings = load_settings()
    assert settings.scoring.thresholds["critical"] == 80


def test_env_expansion_and_types(tmp_path, monkeypatch):
    monkeypatch.setenv("MISP_KEY", "abc")
    monkeypatch.setenv("MISP_ON", "true")
    config = tmp_path / "settings.yaml"
    config.write_text(
        "dedup_window_minutes: ${WINDOW:-15}\n"
        "intel:\n"
        "  misp:\n"
        "    enabled: ${MISP_ON:-false}\n"
        "    api_key: ${MISP_KEY}\n"
        "  abuseipdb:\n"
        "    enabled: ${ABUSE_ON:-false}\n"
    )
    settings = load_settings(config)
    assert settings.dedup_window_minutes == 15
    assert settings.intel.misp.enabled is True
    assert settings.intel.misp.api_key == "abc"
    assert settings.intel.abuseipdb.enabled is False


def test_unknown_keys_are_errors(tmp_path):
    config = tmp_path / "settings.yaml"
    config.write_text("scoring:\n  wieghts: {}\n")
    with pytest.raises(ValueError, match="wieghts"):
        load_settings(config)


def test_shipped_config_is_valid(monkeypatch):
    from conftest import ROOT

    settings = load_settings(ROOT / "config" / "settings.yaml")
    assert settings.intel.misp.enabled is False
