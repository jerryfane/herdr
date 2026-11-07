from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.ci_scope import ZERO_SHA, changed_paths, needs_full_ci


class NeedsFullCiTests(unittest.TestCase):
    def test_a_preview_manifest_pr_skips_the_matrix(self) -> None:
        # The shape of every chore/preview-manifest PR (e.g. #365).
        self.assertFalse(
            needs_full_ci(
                [
                    "distribution/preview.json",
                    "distribution/preview.json.minisig",
                    "docs/preview/website/src/content/docs/socket-api.mdx",
                    "docs/preview/website/src/content/docs/ja/socket-api.mdx",
                ]
            )
        )

    def test_files_the_rust_build_reads_need_the_matrix(self) -> None:
        # Compiled in: the API schema (src/cli/api.rs) and the Windows installer (src/update.rs).
        self.assertTrue(needs_full_ci(["docs/next/api/herdr-api.schema.json"]))
        self.assertTrue(needs_full_ci(["distribution/install.ps1"]))
        self.assertTrue(needs_full_ci(["distribution/latest.json"]))

    def test_one_code_file_among_docs_needs_the_matrix(self) -> None:
        self.assertTrue(needs_full_ci(["README.md", "src/update.rs"]))

    def test_only_top_level_markdown_counts_as_docs(self) -> None:
        self.assertFalse(needs_full_ci(["CHANGELOG.md", "README.md"]))
        self.assertTrue(needs_full_ci(["src/integration/assets/README.md"]))

    def test_no_changed_paths_runs_everything(self) -> None:
        self.assertTrue(needs_full_ci([]))


class ChangedPathsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        self.git("init", "-q")
        self.git("config", "user.email", "ci@example.invalid")
        self.git("config", "user.name", "ci")
        self.commit("README.md", "one")
        self.base = self.git("rev-parse", "HEAD")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def git(self, *args: str) -> str:
        return subprocess.check_output(["git", *args], cwd=self.repo, text=True).strip()

    def commit(self, path: str, text: str) -> None:
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        self.git("add", path)
        self.git("commit", "-q", "-m", f"change {path}")

    def in_repo(self, base: str, head: str) -> list[str] | None:
        cwd = Path.cwd()
        try:
            os.chdir(self.repo)
            return changed_paths(base, head)
        finally:
            os.chdir(cwd)

    def test_lists_the_files_changed_since_base(self) -> None:
        self.commit("docs/a.md", "a")
        self.commit("src/b.rs", "b")
        head = self.git("rev-parse", "HEAD")
        self.assertEqual(sorted(self.in_repo(self.base, head) or []), ["docs/a.md", "src/b.rs"])

    def test_a_new_branch_push_or_unknown_base_is_unresolved(self) -> None:
        head = self.git("rev-parse", "HEAD")
        self.assertIsNone(self.in_repo(ZERO_SHA, head))
        self.assertIsNone(self.in_repo("f" * 40, head))


if __name__ == "__main__":
    unittest.main()
