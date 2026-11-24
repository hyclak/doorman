"""Check CHANGELOG.md against the package version, and print a version's release notes.

Usage:
  python scripts/changelog.py check            # the current __version__ has a dated, non-empty entry
  python scripts/changelog.py notes v0.2.1     # print that version's entry (release notes)

CI runs the same check through tests/test_changelog.py, so a PR that bumps __version__ without
a changelog entry fails. The release workflow runs it again and uses the entry as release notes.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = ROOT / "CHANGELOG.md"
INIT = ROOT / "src" / "doorman" / "__init__.py"

_HEADING = re.compile(r"^## \[(?P<version>[^\]]+)\](?: - (?P<date>\S+))?\s*$", re.MULTILINE)
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def package_version() -> str:
    m = re.search(r'^__version__ = "(.+)"$', INIT.read_text(), re.MULTILINE)
    if not m:
        raise SystemExit(f"no __version__ in {INIT}")
    return m[1]


def entry(text: str, version: str) -> tuple[str | None, str] | None:
    """Return (date, body) for a version's entry, or None if it has none."""
    headings = list(_HEADING.finditer(text))
    for i, h in enumerate(headings):
        if h["version"] == version:
            end = headings[i + 1].start() if i + 1 < len(headings) else len(text)
            body = text[h.end() : end]
            # Stop at the link reference definitions at the bottom of the file.
            body = re.split(r"^\[[^\]]+\]: ", body, maxsplit=1, flags=re.MULTILINE)[0]
            return h["date"], body.strip()
    return None


def problems(text: str, version: str) -> list[str]:
    """Everything wrong with the changelog for this version (empty when it's fine)."""
    found = entry(text, version)
    if found is None:
        return [
            f"CHANGELOG.md has no entry for {version}: rename Unreleased to "
            f"'## [{version}] - YYYY-MM-DD' and add a fresh Unreleased heading"
        ]
    date, body = found
    errors = []
    if not date or not _DATE.match(date):
        errors.append(f"the {version} heading needs a date: '## [{version}] - YYYY-MM-DD'")
    if not body:
        errors.append(f"the {version} entry is empty")
    if not re.search(rf"^\[{re.escape(version)}\]: \S+", text, re.MULTILINE):
        errors.append(f"no comparison link for [{version}] at the bottom of CHANGELOG.md")
    if entry(text, "Unreleased") is None:
        errors.append("CHANGELOG.md needs an '## [Unreleased]' heading above the releases")
    return errors


def main(argv: list[str]) -> int:
    text = CHANGELOG.read_text()
    if argv[:1] == ["check"] and len(argv) == 1:
        version = package_version()
        errors = problems(text, version)
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        if not errors:
            print(f"OK: CHANGELOG.md has an entry for {version}")
        return 1 if errors else 0
    if argv[:1] == ["notes"] and len(argv) == 2:
        version = argv[1].removeprefix("v")
        found = entry(text, version)
        if found is None:
            print(f"error: CHANGELOG.md has no entry for {version}", file=sys.stderr)
            return 1
        print(found[1])
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
