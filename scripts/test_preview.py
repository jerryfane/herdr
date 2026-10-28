import base64
import contextlib
import hashlib
import io
import json
import os
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock
from pathlib import Path

import scripts.conventional_commits as conventional_commits
import scripts.preview as preview

COMMIT = "abcdef1234567890abcdef1234567890abcdef12"
BUILD_ID = "2026-06-02-abcdef123456"
TAG = f"preview-{BUILD_ID}"
SHAS = {
    target: f"{index:x}" * 64
    for index, target in enumerate(preview.ASSET_TARGETS, start=10)
}
SIZES = {target: 4096 + index for index, target in enumerate(preview.ASSET_TARGETS)}


def manifest_kwargs(output: Path, **overrides):
    kwargs = {
        "output": output,
        "repo": "herdrdev/herdr",
        "tag": TAG,
        "build_id": BUILD_ID,
        "commit": COMMIT,
        "commit_time": 1780369200,
        "built_at": "2026-06-02T03:00:00Z",
        "base_version": "0.6.6",
        "protocol": 12,
        "notes": "Preview notes\n",
        "shas": dict(SHAS),
        "sizes": dict(SIZES),
        "retain": 30,
        "endpoint_generation": 77,
    }
    kwargs.update(overrides)
    return kwargs


class PreviewNotesTests(unittest.TestCase):
    def test_notes_contain_only_build_and_comparison_link(self):
        self.assertEqual(
            preview.build_notes("previous-sha", "current-sha", "2026-09-16-abcdef123456", "herdrdev/herdr"),
            "Preview build 2026-09-16-abcdef123456\n\n"
            "[View changes](https://github.com/herdrdev/herdr/compare/previous-sha...current-sha)\n",
        )

    def test_build_manifest_writes_schema_v2_with_commit_time_size_and_sha256(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "preview.json"
            v1_build = {
                "base_version": "0.6.5",
                "commit": "1" * 40,
                "built_at": "2026-05-01T03:00:00Z",
                "protocol": 12,
                "endpoint_generation": 76,
                "tag": "preview-old",
                "assets": {"linux-x86_64": {"url": "https://example.test/old", "sha256": "0" * 64}},
            }
            output.write_text(
                json.dumps({"schema_version": 1, "builds": {"old": v1_build}}),
                encoding="utf-8",
            )
            shas = dict(SHAS, **{"linux-x86_64": "AB" * 32})
            data = json.loads(preview.build_manifest(**manifest_kwargs(output, shas=shas)))

            self.assertEqual(data["schema_version"], 2)
            self.assertEqual(data["channel"], "preview")
            self.assertEqual(data["build_id"], BUILD_ID)
            self.assertEqual(data["endpoint_generation"], 77)
            self.assertIs(type(data["commit_time"]), int)
            self.assertEqual(data["commit_time"], 1780369200)
            build = data["builds"][BUILD_ID]
            self.assertEqual(build["commit_time"], 1780369200)
            self.assertEqual(build["endpoint_generation"], 77)
            self.assertEqual(build["assets"], data["assets"])
            self.assertEqual(set(data["assets"]), set(preview.ASSET_TARGETS))
            for target, asset in data["assets"].items():
                self.assertEqual(asset["sha256"], shas[target].lower())
                self.assertIs(type(asset["size"]), int)
                self.assertEqual(asset["size"], SIZES[target])
            self.assertEqual(
                data["assets"]["windows-x86_64"]["url"],
                f"https://github.com/herdrdev/herdr/releases/download/{TAG}/herdr-windows-x86_64.zip",
            )
            self.assertEqual(data["assets"]["windows-x86_64"]["format"], "zip")
            self.assertNotIn("format", data["assets"]["linux-x86_64"])
            # Archived v1 builds are kept verbatim: no invented commit_time or size.
            self.assertEqual(data["builds"]["old"], v1_build)

    def test_every_preview_asset_requires_sha256(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "preview.json"
            for target in preview.ASSET_TARGETS:
                for bad in (None, "deadbeef", "g" * 64):
                    with self.subTest(target=target, sha=bad):
                        shas = dict(SHAS)
                        if bad is None:
                            del shas[target]
                        else:
                            shas[target] = bad
                        with self.assertRaisesRegex(ValueError, f"{target} requires a SHA-256"):
                            preview.build_manifest(**manifest_kwargs(output, shas=shas))
            self.assertFalse(output.exists())

    def test_every_preview_asset_requires_positive_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "preview.json"
            for target in preview.ASSET_TARGETS:
                for bad in (None, 0, -1, "4096", True, 4096.0):
                    with self.subTest(target=target, size=bad):
                        sizes = dict(SIZES)
                        if bad is None:
                            del sizes[target]
                        else:
                            sizes[target] = bad
                        with self.assertRaisesRegex(ValueError, f"{target} requires a positive byte size"):
                            preview.build_manifest(**manifest_kwargs(output, sizes=sizes))

    def test_build_manifest_requires_commit_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            for bad in (0, -5, "1780369200", None):
                with self.subTest(commit_time=bad):
                    with self.assertRaisesRegex(ValueError, "commit_time"):
                        preview.build_manifest(
                            **manifest_kwargs(Path(tmp) / "preview.json", commit_time=bad)
                        )

    def test_manifest_cli_defaults_commit_time_to_git_committer_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            git_env = {
                **os.environ,
                "GIT_AUTHOR_NAME": "Test",
                "GIT_AUTHOR_EMAIL": "test@example.com",
                "GIT_COMMITTER_NAME": "Test",
                "GIT_COMMITTER_EMAIL": "test@example.com",
                "GIT_AUTHOR_DATE": "@1700000000 +0000",
                "GIT_COMMITTER_DATE": "@1767225600 +0000",
            }

            def git(*args: str) -> str:
                return subprocess.check_output(["git", *args], cwd=repo, env=git_env, text=True).strip()

            git("init", "-q")
            (repo / "README").write_text("preview\n", encoding="utf-8")
            git("add", "README")
            git("commit", "-qm", "preview fixture")
            commit = git("rev-parse", "HEAD")
            (repo / "notes.md").write_text("Preview notes\n", encoding="utf-8")
            (repo / "sha.json").write_text(json.dumps(SHAS), encoding="utf-8")
            (repo / "size.json").write_text(json.dumps(SIZES), encoding="utf-8")
            original_cwd = Path.cwd()
            try:
                os.chdir(repo)
                code = preview.main([
                    "manifest",
                    "--output", "preview.json",
                    "--tag", TAG,
                    "--build-id", BUILD_ID,
                    "--commit", commit,
                    "--built-at", "2026-06-02T03:00:00Z",
                    "--base-version", "0.6.6",
                    "--protocol", "12",
                    "--endpoint-generation", "77",
                    "--notes", "notes.md",
                    "--sha-file", "sha.json",
                    "--size-file", "size.json",
                ])
            finally:
                os.chdir(original_cwd)
            self.assertEqual(code, 0)
            data = json.loads((repo / "preview.json").read_text(encoding="utf-8"))
            self.assertEqual(data["commit_time"], 1767225600)
            self.assertEqual(data["builds"][BUILD_ID]["commit_time"], 1767225600)
            self.assertEqual(data["assets"]["macos-aarch64"]["size"], SIZES["macos-aarch64"])

    def test_preview_range_base_advances_to_stable_tag(self):
        with (
            mock.patch.object(preview, "latest_stable_tag", return_value="v0.7.0"),
            mock.patch.object(preview, "git_is_ancestor", return_value=True),
        ):
            self.assertEqual(
                preview.preview_range_base("previous-preview", "release"),
                "v0.7.0",
            )

    def test_preview_range_base_keeps_previous_preview_for_unreleased_work(self):
        def is_ancestor(ancestor: str, descendant: str) -> bool:
            return (ancestor, descendant) in {
                ("v0.7.0", "new-feature"),
                ("previous-preview", "new-feature"),
            }

        with (
            mock.patch.object(preview, "latest_stable_tag", return_value="v0.7.0"),
            mock.patch.object(preview, "git_is_ancestor", side_effect=is_ancestor),
        ):
            self.assertEqual(
                preview.preview_range_base("previous-preview", "new-feature"),
                "previous-preview",
            )

    def test_hotfix_preview_uses_stable_base_instead_of_newer_master_preview(self):
        with (
            mock.patch.object(preview, "latest_stable_tag", return_value="v0.7.0"),
            mock.patch.object(preview, "git_is_ancestor", return_value=False),
        ):
            self.assertEqual(preview.preview_range_base("newer-master", "hotfix"), "v0.7.0")

    def test_post_stable_history_bases_range_on_stable_tag(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)

            def git(*args: str) -> str:
                return subprocess.check_output(
                    ["git", *args],
                    cwd=repo,
                    text=True,
                    stderr=subprocess.DEVNULL,
                ).strip()

            git("init")
            git("config", "user.email", "test@example.com")
            git("config", "user.name", "Test User")

            marker = repo / "marker.txt"
            marker.write_text("preview\n", encoding="utf-8")
            git("add", "marker.txt")
            git("commit", "-m", "feat: previous preview")
            previous_preview = git("rev-parse", "HEAD")

            marker.write_text("release\n", encoding="utf-8")
            git("commit", "-am", "release: v0.7.0")
            release = git("rev-parse", "HEAD")
            git("tag", "v0.7.0")

            original_cwd = os.getcwd()
            try:
                os.chdir(repo)
                self.assertEqual(
                    preview.preview_range_base(previous_preview, release),
                    "v0.7.0",
                )
            finally:
                os.chdir(original_cwd)


def fake_minisig(trusted_comment: str, algorithm: bytes = b"ED") -> str:
    # Shape of a real minisign signature; the Python side checks structure, not cryptography.
    signature = algorithm + bytes.fromhex("0123456789abcdef") + bytes(range(64))
    global_signature = bytes(range(64, 128))
    return (
        "untrusted comment: signature from minisign secret key\n"
        f"{base64.b64encode(signature).decode()}\n"
        f"trusted comment: {trusted_comment}\n"
        f"{base64.b64encode(global_signature).decode()}\n"
    )


class StubKeyring:
    """Role-scoped keyring relay stand-in on 127.0.0.1:<ephemeral>."""

    ROUTE = "/herdr-app/_keyring/minisign/herdr-release"

    def __init__(self, respond):
        self.respond = respond
        self.requests: list[dict] = []
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                stub.requests.append({
                    "path": self.path,
                    "content_type": self.headers.get("Content-Type"),
                    "body": body,
                })
                status, payload = stub.respond(json.loads(body))
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}{self.ROUTE}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


def minisig_response(make_text):
    def respond(request: dict):
        return 200, json.dumps({"minisig": make_text(request["trusted_comment"])}).encode()

    return respond


class PreviewSignTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.manifest = self.dir / "preview.json"
        self.manifest.write_text(
            preview.build_manifest(**manifest_kwargs(self.manifest)), encoding="utf-8"
        )
        self.manifest_bytes = self.manifest.read_bytes()
        self.trusted_comment = f"herdr-preview {BUILD_ID} {COMMIT}"

    def sign(self, url: str) -> tuple[int, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = preview.main([
                "sign", "--manifest", str(self.manifest), "--keyring-url", url, "--timeout", "10",
            ])
        return code, stdout.getvalue(), stderr.getvalue()

    def assert_refused(self, respond, message: str) -> StubKeyring:
        with StubKeyring(respond) as stub:
            code, stdout, stderr = self.sign(stub.url)
        self.assertEqual(code, 1)
        self.assertEqual(stdout, "")
        self.assertRegex(stderr, message)
        self.assertEqual(sorted(os.listdir(self.dir)), ["preview.json"])
        self.assertEqual(self.manifest.read_bytes(), self.manifest_bytes)
        return stub

    def test_sign_posts_blake2b_and_trusted_comment_then_writes_minisig_verbatim(self):
        minisig = fake_minisig(self.trusted_comment)
        with StubKeyring(lambda request: (200, json.dumps({"minisig": minisig}).encode())) as stub:
            code, stdout, stderr = self.sign(stub.url)

        self.assertEqual((code, stderr), (0, ""))
        signature_path = self.dir / "preview.json.minisig"
        self.assertEqual(stdout.strip(), str(signature_path))
        self.assertEqual(len(stub.requests), 1)
        request = stub.requests[0]
        self.assertEqual(request["path"], StubKeyring.ROUTE)
        self.assertEqual(request["content_type"], "application/json")
        digest = hashlib.blake2b(self.manifest_bytes, digest_size=64).hexdigest()
        self.assertRegex(digest, r"^[0-9a-f]{128}$")
        self.assertEqual(
            json.loads(request["body"]),
            {"blake2b512_hex": digest, "trusted_comment": self.trusted_comment},
        )
        self.assertEqual(signature_path.read_bytes(), minisig.encode("ascii"))
        self.assertEqual(sorted(os.listdir(self.dir)), ["preview.json", "preview.json.minisig"])
        self.assertEqual(self.manifest.read_bytes(), self.manifest_bytes)

    def test_sign_refuses_legacy_ed_signature(self):
        self.assert_refused(
            minisig_response(lambda comment: fake_minisig(comment, algorithm=b"Ed")),
            "expected prehashed b'ED'",
        )

    def test_sign_refuses_wrong_trusted_comment(self):
        other_build = f"herdr-preview 2026-05-01-000000000000 {COMMIT}"
        for comment in (other_build, f"{self.trusted_comment} extra", f"herdr-preview {BUILD_ID} {COMMIT[:12]}"):
            with self.subTest(comment=comment):
                self.assert_refused(
                    minisig_response(lambda _requested, comment=comment: fake_minisig(comment)),
                    "trusted comment must be exactly",
                )

    def test_sign_refuses_malformed_minisig(self):
        def drop_last_line(comment: str) -> str:
            return "\n".join(fake_minisig(comment).splitlines()[:3]) + "\n"

        def bad_base64(comment: str) -> str:
            lines = fake_minisig(comment).splitlines()
            lines[1] = "not*base64"
            return "\n".join(lines) + "\n"

        def short_signature(comment: str) -> str:
            lines = fake_minisig(comment).splitlines()
            lines[1] = base64.b64encode(b"ED" + bytes(40)).decode()
            return "\n".join(lines) + "\n"

        def no_untrusted_comment(comment: str) -> str:
            return fake_minisig(comment).replace("untrusted comment: ", "comment: ", 1)

        def short_global_signature(comment: str) -> str:
            lines = fake_minisig(comment).splitlines()
            lines[3] = base64.b64encode(bytes(32)).decode()
            return "\n".join(lines) + "\n"

        cases = {
            "three lines": (minisig_response(drop_last_line), "3 lines, expected 4"),
            "bad base64": (minisig_response(bad_base64), "signature line is not base64"),
            "short signature": (minisig_response(short_signature), "42 bytes, expected 74"),
            "untrusted comment": (minisig_response(no_untrusted_comment), "untrusted comment"),
            "global signature": (minisig_response(short_global_signature), "global signature is 32 bytes"),
            "no minisig key": (lambda request: (200, b'{"signature": "x"}'), "no minisig text"),
            "not json": (lambda request: (200, b"minisig"), "invalid JSON"),
        }
        for name, (respond, message) in cases.items():
            with self.subTest(name):
                self.assert_refused(respond, message)

    def test_sign_refuses_http_error(self):
        minisig = fake_minisig(self.trusted_comment)
        stub = self.assert_refused(
            lambda request: (500, json.dumps({"minisig": minisig}).encode()),
            "HTTP 500",
        )
        self.assertEqual(len(stub.requests), 1)

    def test_sign_refuses_v1_manifest_without_contacting_relay(self):
        data = json.loads(self.manifest_bytes)
        data["schema_version"] = 1
        self.manifest.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        self.manifest_bytes = self.manifest.read_bytes()
        stub = self.assert_refused(
            minisig_response(fake_minisig), "manifest must be schema_version 2"
        )
        self.assertEqual(stub.requests, [])


class ConventionalCommitTests(unittest.TestCase):
    def test_valid_subjects_allow_scopes_and_bang(self):
        self.assertTrue(conventional_commits.valid_subject("fix(update): handle preview"))
        self.assertTrue(conventional_commits.valid_subject("feat!: change config"))
        self.assertFalse(conventional_commits.valid_subject("update preview channel"))

    def test_commit_message_subject_skips_comments(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "COMMIT_EDITMSG"
            path.write_text(
                "\n# Please enter the commit message\n\nfix(update): switch channel\n",
                encoding="utf-8",
            )
            self.assertEqual(
                conventional_commits.commit_message_subject(path),
                "fix(update): switch channel",
            )


if __name__ == "__main__":
    unittest.main()
