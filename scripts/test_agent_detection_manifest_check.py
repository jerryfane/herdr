import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import agent_detection_manifest_check as check


def manifest(agent_id: str, version: str, contains: str = "ready") -> str:
    return f'''id = "{agent_id}"
version = "{version}"
min_engine_version = 1
updated_at = "2026-06-10T00:00:00Z"

[[rules]]
id = "idle"
state = "idle"
contains = ["{contains}"]
'''


def catalog(agent_id: str = "codex", path: str = "codex.toml") -> str:
    return f'''schema_version = 1

[[agents]]
id = "{agent_id}"
path = "{path}"
'''


# The staged-manifest fixture is SYNTHETIC on purpose. It used to copy the live
# grok manifests out of the repo and lean on the live STAGED_PUBLISHED_MANIFESTS
# entry, so the moment grok was actually published (v0.9.0 merge: engine 5 makes
# the engine-3 manifest publishable) these tests stopped exercising staging at
# all and started failing on unrelated content drift. The mechanism must be
# testable without depending on what today's catalog happens to hold.
STAGED_BUNDLED_VERSION = "2026.06.10.2"
STAGED_PUBLISHED_VERSION = "2026.06.10.1"
STAGED_ENGINE_VERSION = 3


def staged_manifest_dirs(root: Path) -> tuple[Path, Path, dict[str, tuple[str, str, str]]]:
    """A bundled manifest that needs the CURRENT engine, published one behind."""
    bundled = root / "bundled"
    published = root / "published"
    bundled.mkdir()
    published.mkdir()
    bundled_content = manifest("staged", STAGED_BUNDLED_VERSION).replace(
        "min_engine_version = 1", f"min_engine_version = {STAGED_ENGINE_VERSION}"
    )
    published_content = manifest("staged", STAGED_PUBLISHED_VERSION).replace(
        "min_engine_version = 1", f"min_engine_version = {STAGED_ENGINE_VERSION - 1}"
    )
    (bundled / "staged.toml").write_text(bundled_content)
    (published / "staged.toml").write_text(published_content)
    (published / "index.toml").write_text(catalog("staged", "staged.toml"))
    staged = {
        "staged": (
            STAGED_BUNDLED_VERSION,
            STAGED_PUBLISHED_VERSION,
            hashlib.sha256(published_content.encode()).hexdigest(),
        )
    }
    return bundled, published, staged


UNPUBLISHED_TEST_MANIFEST = manifest("testagent", "2026.06.10.1")
UNPUBLISHED_TEST_EXCEPTION = {
    "testagent": (
        "2026.06.10.1",
        hashlib.sha256(UNPUBLISHED_TEST_MANIFEST.encode()).hexdigest(),
    ),
}


def unpublished_manifest_dirs(root: Path) -> tuple[Path, Path]:
    bundled = root / "bundled"
    published = root / "published"
    bundled.mkdir()
    published.mkdir()
    (bundled / "testagent.toml").write_text(UNPUBLISHED_TEST_MANIFEST, encoding="utf-8", newline="\n")
    (published / "index.toml").write_text("schema_version = 1\nagents = []\n")
    return bundled, published


class AgentDetectionManifestCheckTests(unittest.TestCase):
    def test_validates_bundled_and_matching_published_catalog(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundled = root / "bundled"
            website = root / "website"
            bundled.mkdir()
            website.mkdir()
            content = manifest("codex", "2026.06.10.1")
            (bundled / "codex.toml").write_text(content)
            (website / "codex.toml").write_text(content)
            (website / "index.toml").write_text(catalog())

            bundled_manifests = check.load_manifest_dir(bundled, engine_version=1)
            check.validate_catalog(website, bundled_manifests, engine_version=1)

    def test_rejects_published_version_lower_than_bundled(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundled = root / "bundled"
            website = root / "website"
            bundled.mkdir()
            website.mkdir()
            (bundled / "codex.toml").write_text(manifest("codex", "2026.06.10.2"))
            (website / "codex.toml").write_text(manifest("codex", "2026.06.10.1"))
            (website / "index.toml").write_text(catalog())

            bundled_manifests = check.load_manifest_dir(bundled, engine_version=1)
            with self.assertRaisesRegex(check.CheckError, "lower than bundled"):
                check.validate_catalog(website, bundled_manifests, engine_version=1)

    def test_allows_explicitly_staged_published_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundled, published, staged = staged_manifest_dirs(Path(tmp))

            bundled_manifests = check.load_manifest_dir(
                bundled, engine_version=STAGED_ENGINE_VERSION
            )
            with patch.object(check, "STAGED_PUBLISHED_MANIFESTS", staged):
                check.validate_catalog(
                    published, bundled_manifests, engine_version=STAGED_ENGINE_VERSION
                )

    def test_rejects_mutated_staged_published_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundled, published, staged = staged_manifest_dirs(Path(tmp))
            with (published / "staged.toml").open("a") as manifest_file:
                manifest_file.write("\n# unexpected mutation\n")

            bundled_manifests = check.load_manifest_dir(
                bundled, engine_version=STAGED_ENGINE_VERSION
            )
            with patch.object(check, "STAGED_PUBLISHED_MANIFESTS", staged):
                with self.assertRaisesRegex(check.CheckError, "lower than bundled"):
                    check.validate_catalog(
                        published, bundled_manifests, engine_version=STAGED_ENGINE_VERSION
                    )

    def test_rejects_unlisted_published_manifest_lag_for_new_engine(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundled = root / "bundled"
            website = root / "website"
            bundled.mkdir()
            website.mkdir()
            bundled_content = manifest("codex", "2026.06.10.2").replace(
                "min_engine_version = 1", "min_engine_version = 2"
            )
            (bundled / "codex.toml").write_text(bundled_content)
            (website / "codex.toml").write_text(manifest("codex", "2026.06.10.1"))
            (website / "index.toml").write_text(catalog())

            bundled_manifests = check.load_manifest_dir(bundled, engine_version=2)
            with self.assertRaisesRegex(check.CheckError, "lower than bundled"):
                check.validate_catalog(website, bundled_manifests, engine_version=2)

    def test_rejects_same_version_content_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundled = root / "bundled"
            website = root / "website"
            bundled.mkdir()
            website.mkdir()
            (bundled / "codex.toml").write_text(manifest("codex", "2026.06.10.1", "ready"))
            (website / "codex.toml").write_text(manifest("codex", "2026.06.10.1", "changed"))
            (website / "index.toml").write_text(catalog())

            bundled_manifests = check.load_manifest_dir(bundled, engine_version=1)
            with self.assertRaisesRegex(check.CheckError, "same version"):
                check.validate_catalog(website, bundled_manifests, engine_version=1)

    @patch.dict(check.UNPUBLISHED_BUNDLED_MANIFESTS, UNPUBLISHED_TEST_EXCEPTION, clear=True)
    def test_allows_exact_unpublished_bundled_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundled, published = unpublished_manifest_dirs(Path(tmp))
            bundled_manifests = check.load_manifest_dir(bundled, engine_version=3)
            check.validate_catalog(
                published,
                bundled_manifests,
                engine_version=3,
                allow_unpublished=True,
            )

    @patch.dict(check.UNPUBLISHED_BUNDLED_MANIFESTS, UNPUBLISHED_TEST_EXCEPTION, clear=True)
    def test_release_gate_rejects_exact_unpublished_bundled_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundled, published = unpublished_manifest_dirs(Path(tmp))
            bundled_manifests = check.load_manifest_dir(bundled, engine_version=3)
            with self.assertRaisesRegex(check.CheckError, "missing bundled agent"):
                check.validate_catalog(published, bundled_manifests, engine_version=3)

    @patch.dict(check.UNPUBLISHED_BUNDLED_MANIFESTS, UNPUBLISHED_TEST_EXCEPTION, clear=True)
    def test_rejects_mutated_unpublished_bundled_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundled, published = unpublished_manifest_dirs(Path(tmp))
            with (bundled / "testagent.toml").open("a") as manifest_file:
                manifest_file.write("\n# unexpected mutation\n")
            bundled_manifests = check.load_manifest_dir(bundled, engine_version=3)
            with self.assertRaisesRegex(check.CheckError, "missing bundled agent"):
                check.validate_catalog(
                    published,
                    bundled_manifests,
                    engine_version=3,
                    allow_unpublished=True,
                )

    def test_rejects_unknown_catalog_agent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundled = root / "bundled"
            website = root / "website"
            bundled.mkdir()
            website.mkdir()
            (bundled / "codex.toml").write_text(manifest("codex", "2026.06.10.1"))
            (website / "newagent.toml").write_text(manifest("newagent", "2026.06.10.1"))
            (website / "index.toml").write_text(catalog("newagent", "newagent.toml"))

            bundled_manifests = check.load_manifest_dir(bundled, engine_version=1)
            with self.assertRaisesRegex(check.CheckError, "unknown agent"):
                check.validate_catalog(website, bundled_manifests, engine_version=1)

    def test_rejects_manifest_requiring_newer_engine(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundled = Path(tmp) / "bundled"
            bundled.mkdir()
            (bundled / "codex.toml").write_text(
                manifest("codex", "2026.06.10.1").replace(
                    "min_engine_version = 1", "min_engine_version = 2"
                )
            )

            with self.assertRaisesRegex(check.CheckError, "exceeds engine"):
                check.load_manifest_dir(bundled, engine_version=1)

    def test_rejects_top_non_empty_lines_below_engine_three(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundled = Path(tmp) / "bundled"
            bundled.mkdir()
            content = manifest("codex", "2026.06.10.1").replace(
                'contains = ["ready"]',
                'region = "top_non_empty_lines(1)"\ncontains = ["ready"]',
            )
            (bundled / "codex.toml").write_text(content)

            with self.assertRaisesRegex(check.CheckError, "requires min_engine_version 3"):
                check.load_manifest_dir(bundled, engine_version=3)

    def test_top_non_empty_lines_requires_canonical_positive_bounded_count(self):
        base_rule = {
            "id": "test",
            "state": "working",
            "contains": ["ready"],
        }
        name = "top_non_empty_lines"
        for count in ("1", str(check.MAX_TOP_REGION_LINE_COUNT)):
            rule = {**base_rule, "region": f"{name}({count})"}
            check.validate_rule(Path("test.toml"), 0, rule, {"gates": 0, "matchers": 0})
        for count in (
            "0",
            "01",
            "+1",
            str(check.MAX_TOP_REGION_LINE_COUNT + 1),
            "9" * 40,
        ):
            rule = {**base_rule, "region": f"{name}({count})"}
            with self.subTest(region=rule["region"]):
                with self.assertRaisesRegex(check.CheckError, "invalid region"):
                    check.validate_rule(
                        Path("test.toml"), 0, rule, {"gates": 0, "matchers": 0}
                    )


class ForkManifestSectionTests(unittest.TestCase):
    """The `composer` / `input_rules` sections are fork-only.

    Upstream's copy of the checker does not know them, so a future upstream sync
    that overwrites this script silently rejects every bundled fork manifest.
    These tests fail loudly if that happens again.
    """

    def _manifest_with_sections(self, *, composer_region="prompt_box_body", kind="confirm"):
        return manifest("claudeish", "2026.06.10.1") + f'''
[composer]
region = "{composer_region}"

[[input_rules]]
id = "confirm_prompt"
priority = 100
region = "bottom_non_empty_lines(4)"
kind = "{kind}"
contains = ["(y/n)"]
'''

    def _validate(self, content: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "claudeish.toml"
            path.write_text(content)
            check.validate_manifest(path, engine_version=1)

    def test_accepts_composer_and_input_rules(self):
        self._validate(self._manifest_with_sections())

    def test_rejects_unknown_composer_field(self):
        content = self._manifest_with_sections().replace(
            '[composer]', '[composer]\nunexpected = true'
        )
        with self.assertRaisesRegex(check.CheckError, "unknown composer field"):
            self._validate(content)

    def test_rejects_unknown_input_prompt_kind(self):
        with self.assertRaisesRegex(check.CheckError, "kind must be one of"):
            self._validate(self._manifest_with_sections(kind="interpretive_dance"))

    def test_rejects_unknown_composer_region(self):
        with self.assertRaisesRegex(check.CheckError, "composer.region must be a known region"):
            self._validate(self._manifest_with_sections(composer_region="somewhere_else"))

    def test_shared_rule_manifest_needs_no_version(self):
        """`shared-input.toml` is bundled-only and versionless by design."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "shared-input.toml"
            path.write_text(
                '''id = "shared"
min_engine_version = 1

[[input_rules]]
id = "shared_confirm"
kind = "confirm"
region = "bottom_non_empty_lines(4)"
contains = ["(y/n)"]
'''
            )
            check.validate_shared_rule_manifest(path, engine_version=1)

    def test_shared_rule_manifest_rejects_agent_only_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "shared-input.toml"
            path.write_text(
                '''id = "shared"
version = "2026.06.10.1"
min_engine_version = 1

[[input_rules]]
id = "shared_confirm"
kind = "confirm"
contains = ["(y/n)"]
'''
            )
            with self.assertRaisesRegex(check.CheckError, "unknown shared rule manifest field"):
                check.validate_shared_rule_manifest(path, engine_version=1)


if __name__ == "__main__":
    unittest.main()
