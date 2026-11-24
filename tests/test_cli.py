"""Command-line entry point."""

from doorman import __version__
from doorman.__main__ import main as cli


def test_version_prints_without_config(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("DOORMAN_SECRET_KEY", raising=False)
    cli(["--config", str(tmp_path / "missing.toml"), "version"])
    assert capsys.readouterr().out == f"{__version__}\n"
