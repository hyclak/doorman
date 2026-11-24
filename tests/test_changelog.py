"""CHANGELOG.md must have an entry for the package version, so a version bump can't skip it."""

import importlib.util
from pathlib import Path

import pytest

from doorman import __version__

_spec = importlib.util.spec_from_file_location(
    "changelog", Path(__file__).resolve().parent.parent / "scripts" / "changelog.py"
)
assert _spec and _spec.loader
changelog = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(changelog)

GOOD = """# Changelog

## [Unreleased]

## [1.2.0] - 2026-01-02

### Added
- A thing.

## [1.1.0] - 2026-01-01

### Fixed
- Another thing.

[Unreleased]: https://example.com/compare/v1.2.0...HEAD
[1.2.0]: https://example.com/compare/v1.1.0...v1.2.0
[1.1.0]: https://example.com/releases/tag/v1.1.0
"""


def test_changelog_has_entry_for_current_version():
    errors = changelog.problems(changelog.CHANGELOG.read_text(), __version__)
    assert not errors, "\n".join(errors)


def test_package_version_matches_init():
    assert changelog.package_version() == __version__


def test_good_changelog_passes():
    assert changelog.problems(GOOD, "1.2.0") == []
    assert changelog.problems(GOOD, "1.1.0") == []


def test_entry_body_excludes_other_versions_and_links():
    assert changelog.entry(GOOD, "1.2.0") == ("2026-01-02", "### Added\n- A thing.")
    assert changelog.entry(GOOD, "1.1.0") == ("2026-01-01", "### Fixed\n- Another thing.")


@pytest.mark.parametrize(
    ("text", "message"),
    [
        (GOOD.replace("## [1.2.0] - 2026-01-02", "## [1.1.9] - 2026-01-02"), "no entry for 1.2.0"),
        (GOOD.replace("## [1.2.0] - 2026-01-02", "## [1.2.0]"), "needs a date"),
        (GOOD.replace("## [1.2.0] - 2026-01-02", "## [1.2.0] - soon"), "needs a date"),
        (GOOD.replace("### Added\n- A thing.\n", ""), "entry is empty"),
        (GOOD.replace("[1.2.0]: https://example.com/compare/v1.1.0...v1.2.0\n", ""), "comparison link"),
        (GOOD.replace("## [Unreleased]\n\n", ""), "Unreleased"),
    ],
)
def test_problems_are_reported(text, message):
    errors = changelog.problems(text, "1.2.0")
    assert any(message in e for e in errors), errors


def test_notes_prints_the_entry(capsys):
    assert changelog.main(["notes", f"v{__version__}"]) == 0
    assert capsys.readouterr().out.strip() == changelog.entry(changelog.CHANGELOG.read_text(), __version__)[1]


def test_notes_for_unknown_version_fails(capsys):
    assert changelog.main(["notes", "v0.0.0-nope"]) == 1
