#!/usr/bin/env python3
"""Decides whether a change needs the full CI matrix or only the docs checks.

A change touching only published docs, the preview manifest or top-level Markdown cannot
change what the Rust build, its tests or the Windows package do, so CI skips the three-OS
`check` matrix and the ConPTY package for it and runs `just maintenance-test` instead (the
translation-parity, config-reference, preview and changelog checks those files do affect).

Paths the Rust build reads are code even under docs/ or distribution/:
docs/next/api/ (the API schema, compiled in by src/cli/api.rs) and anything in
distribution/ except the preview manifest and its signature (install.ps1 is compiled in by
src/update.rs). Unknown or missing history is treated as code.
"""
from __future__ import annotations

import argparse
import subprocess
import sys

DOCS_ONLY_FILES = {
    "distribution/preview.json",
    "distribution/preview.json.minisig",
}
CODE_PREFIXES = ("docs/next/api/",)
ZERO_SHA = "0" * 40


def is_docs_only_path(path: str) -> bool:
    if path.startswith(CODE_PREFIXES):
        return False
    if path in DOCS_ONLY_FILES:
        return True
    if path.startswith("docs/"):
        return True
    return "/" not in path and path.endswith(".md")


def needs_full_ci(paths: list[str]) -> bool:
    """True unless every changed path is docs-only. No paths means unknown: run everything."""
    return not paths or not all(is_docs_only_path(path) for path in paths)


def changed_paths(base: str, head: str) -> list[str] | None:
    """Files changed from `base` to `head`, or None when the range cannot be resolved."""
    if not base or not head or base == ZERO_SHA:
        return None
    result = subprocess.run(
        ["git", "diff", "--name-only", f"{base}...{head}"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    return [line for line in result.stdout.splitlines() if line]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("base", help="base commit (PR base or the push's `before`)")
    parser.add_argument("head", help="head commit")
    args = parser.parse_args(argv)
    paths = changed_paths(args.base, args.head)
    full = paths is None or needs_full_ci(paths)
    print(f"code={'true' if full else 'false'}")
    print(
        f"{'full CI' if full else 'docs-only'}: "
        f"{'unresolved range' if paths is None else f'{len(paths)} changed path(s)'}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
