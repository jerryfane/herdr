from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = REPO_ROOT / "install.sh"
BUILD_ID = "2026-08-29-32b2b45b14c7"
TAG = f"preview-{BUILD_ID}"
MANIFEST_URL = "https://example.test/preview.json"
RELEASE_ROOT = "https://github.com/jerryfane/herdr/releases/download"
REQUIRED_COMMANDS = (
    "awk",
    "chmod",
    "cp",
    "id",
    "mkdir",
    "mktemp",
    "mv",
    "rm",
    "sha256sum",
    "stat",
)


class ForkInstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="herdr-fork-installer-test-")
        self.root = Path(self.temp_dir.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.fake_bin = self.root / "fake-bin"
        self.fake_bin.mkdir()
        self.install_dir = self.home / "custom" / "bin"
        self.log = self.root / "commands.log"
        self.manifest = self.root / "preview.json"
        self.binary_content = b"new-herdr\n"

        for command in REQUIRED_COMMANDS:
            path = shutil.which(command)
            if path is None:
                self.fail(f"test host is missing required command: {command}")
            (self.fake_bin / command).symlink_to(path)

        self._write_executable(
            "uname",
            """#!/bin/sh
case "$1" in
    -s) printf '%s\n' "${FAKE_UNAME_SYSTEM:-Linux}" ;;
    -m) printf '%s\n' "${FAKE_UNAME_ARCH:-x86_64}" ;;
    *) exit 2 ;;
esac
""",
        )
        self._write_executable(
            "curl",
            """#!/bin/sh
output=
url=
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o)
            shift
            [ "$#" -gt 0 ] || exit 2
            output=$1
            ;;
        http://*|https://*) url=$1 ;;
    esac
    shift
done
[ -n "$output" ] && [ -n "$url" ] || exit 3
printf 'curl:%s\n' "$url" >> "$FAKE_LOG"
if [ "$url" = "$FAKE_MANIFEST_URL" ]; then
    [ "${FAKE_MANIFEST_FAIL:-0}" != 1 ] || exit 22
    cp "$FAKE_MANIFEST_PATH" "$output"
elif [ "$url" = "$FAKE_ASSET_URL" ]; then
    [ "${FAKE_DOWNLOAD_FAIL:-0}" != 1 ] || exit 22
    printf '%s' "$FAKE_BINARY_CONTENT" > "$output"
else
    exit 23
fi
""",
        )
        self._write_manifest()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _asset_url(self, target: str = "linux-x86_64") -> str:
        return f"{RELEASE_ROOT}/{TAG}/herdr-{target}"

    def _write_manifest(
        self,
        *,
        target: str = "linux-x86_64",
        url: str | None = None,
        sha256: str | None = None,
        build_id: str = BUILD_ID,
        tag: str = TAG,
    ) -> None:
        asset_url = url or self._asset_url(target)
        digest = sha256 or hashlib.sha256(self.binary_content).hexdigest()
        data = {
            "schema_version": 1,
            "channel": "preview",
            "base_version": "0.8.2",
            "build_id": build_id,
            "commit": "3" * 40,
            "assets": [target],
            "builds": {
                "2026-08-01-archived": {
                    "tag": "preview-2026-08-01-archived",
                    "assets": {
                        target: {
                            "url": (
                                f"{RELEASE_ROOT}/preview-2026-08-01-archived/"
                                f"herdr-{target}"
                            ),
                            "sha256": "0" * 64,
                        }
                    },
                },
                build_id: {
                    "tag": tag,
                    "assets": {target: {"url": asset_url, "sha256": digest}},
                },
            },
        }
        self.manifest.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    def _write_executable(self, name: str, content: str) -> None:
        path = self.fake_bin / name
        path.unlink(missing_ok=True)
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)

    def _run(
        self,
        *,
        include_install_dir_on_path: bool = False,
        **overrides: str,
    ) -> subprocess.CompletedProcess[str]:
        path_parts = [str(self.fake_bin)]
        if include_install_dir_on_path:
            path_parts.insert(0, str(self.install_dir))
        env = {
            "HOME": str(self.home),
            "PATH": os.pathsep.join(path_parts),
            "FAKE_ASSET_URL": self._asset_url(),
            "FAKE_BINARY_CONTENT": self.binary_content.decode("utf-8"),
            "FAKE_LOG": str(self.log),
            "FAKE_MANIFEST_PATH": str(self.manifest),
            "FAKE_MANIFEST_URL": MANIFEST_URL,
            "HERDR_BIN_DIR": str(self.install_dir),
            "HERDR_MANIFEST_URL": MANIFEST_URL,
            "TMPDIR": str(self.root),
            **overrides,
        }
        return subprocess.run(
            ["/bin/sh", str(INSTALLER)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def _installed_binary(self) -> Path:
        return self.install_dir / "herdr"

    def _command_log(self) -> str:
        return self.log.read_text(encoding="utf-8") if self.log.exists() else ""

    def test_installs_current_verified_asset_without_a_source_toolchain(self) -> None:
        result = self._run(include_install_dir_on_path=True)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self._installed_binary().read_bytes(), self.binary_content)
        self.assertIn(f"curl:{MANIFEST_URL}", self._command_log())
        self.assertIn(f"curl:{self._asset_url()}", self._command_log())
        self.assertNotIn("archived", self._command_log())
        self.assertIn(f"Installed {self._installed_binary()} from {TAG}", result.stdout)
        self.assertFalse(list(self.root.glob("herdr-fork-installer.*")))
        for source_tool in ("cargo", "git", "rustc", "rustup", "zig"):
            self.assertIsNone(shutil.which(source_tool, path=str(self.fake_bin)))

    def test_installer_and_preview_updaters_share_the_fork_manifest(self) -> None:
        manifest_url = (
            "https://raw.githubusercontent.com/jerryfane/herdr/master/"
            "website/preview.json"
        )
        installer = INSTALLER.read_text(encoding="utf-8")
        updater = (REPO_ROOT / "src" / "update.rs").read_text(encoding="utf-8")
        remote = (REPO_ROOT / "src" / "remote" / "attach.rs").read_text(encoding="utf-8")

        self.assertIn(f'DEFAULT_MANIFEST_URL="{manifest_url}"', installer)
        self.assertIn(manifest_url, updater)
        self.assertIn(manifest_url, remote)

    def test_archived_asset_is_not_selected_for_current_build(self) -> None:
        result = self._run()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("preview-2026-08-01-archived", self._command_log())
        self.assertEqual(self._installed_binary().read_bytes(), self.binary_content)

    def test_checksum_mismatch_preserves_existing_binary(self) -> None:
        self.install_dir.mkdir(parents=True)
        self._installed_binary().write_text("working-herdr\n", encoding="utf-8")
        self._write_manifest(sha256="f" * 64)

        result = self._run()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum did not match", result.stderr)
        self.assertEqual(self._installed_binary().read_text(encoding="utf-8"), "working-herdr\n")

    def test_wrong_repository_url_fails_before_asset_download(self) -> None:
        wrong_url = f"https://github.com/herdrdev/herdr/releases/download/{TAG}/herdr-linux-x86_64"
        self._write_manifest(url=wrong_url)

        result = self._run()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not resolve to jerryfane/herdr", result.stderr)
        self.assertEqual(self._command_log(), f"curl:{MANIFEST_URL}\n")
        self.assertFalse(self._installed_binary().exists())

    def test_release_tag_path_injection_is_rejected_before_download(self) -> None:
        self._write_manifest(tag="preview-safe/../../other")

        result = self._run()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid release tag", result.stderr)
        self.assertEqual(self._command_log(), f"curl:{MANIFEST_URL}\n")

    def test_missing_target_fails_before_asset_download(self) -> None:
        self._write_manifest(target="linux-aarch64")

        result = self._run()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("has no binary for linux-x86_64", result.stderr)
        self.assertEqual(self._command_log(), f"curl:{MANIFEST_URL}\n")

    def test_malformed_checksum_is_rejected_before_download(self) -> None:
        self._write_manifest(sha256="g" * 64)

        result = self._run()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum is not hexadecimal", result.stderr)
        self.assertEqual(self._command_log(), f"curl:{MANIFEST_URL}\n")

    def test_manifest_download_failure_preserves_existing_binary(self) -> None:
        self.install_dir.mkdir(parents=True)
        self._installed_binary().write_text("working-herdr\n", encoding="utf-8")

        result = self._run(FAKE_MANIFEST_FAIL="1")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not download the fork preview manifest", result.stderr)
        self.assertEqual(self._installed_binary().read_text(encoding="utf-8"), "working-herdr\n")

    def test_asset_download_failure_preserves_existing_binary(self) -> None:
        self.install_dir.mkdir(parents=True)
        self._installed_binary().write_text("working-herdr\n", encoding="utf-8")

        result = self._run(FAKE_DOWNLOAD_FAIL="1")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("installed binary was not changed", result.stderr)
        self.assertEqual(self._installed_binary().read_text(encoding="utf-8"), "working-herdr\n")

    def test_failed_atomic_promotion_preserves_existing_binary(self) -> None:
        self.install_dir.mkdir(parents=True)
        self._installed_binary().write_text("working-herdr\n", encoding="utf-8")
        self._write_executable("mv", "#!/bin/sh\nexit 19\n")

        result = self._run()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not activate", result.stderr)
        self.assertEqual(self._installed_binary().read_text(encoding="utf-8"), "working-herdr\n")
        self.assertFalse(list(self.install_dir.glob(".herdr-install.*")))

    def test_install_directory_must_stay_below_home(self) -> None:
        outside_bin = self.root / "outside-home" / "bin"

        result = self._run(HERDR_BIN_DIR=str(outside_bin))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be an absolute path below HOME", result.stderr)
        self.assertFalse(outside_bin.exists())
        self.assertEqual(self._command_log(), "")

    def test_symlinked_install_directory_is_refused_before_download(self) -> None:
        outside_dir = self.root / "outside-home"
        outside_dir.mkdir()
        (self.home / "linked").symlink_to(outside_dir, target_is_directory=True)

        result = self._run(HERDR_BIN_DIR=str(self.home / "linked" / "bin"))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is a symlink; refusing to follow it", result.stderr)
        self.assertFalse((outside_dir / "bin").exists())
        self.assertEqual(self._command_log(), "")

    def test_repeat_run_is_idempotent_and_wrong_path_binary_is_reported(self) -> None:
        self._write_executable("herdr", "#!/bin/sh\nexit 0\n")
        first = self._run()
        second = self._run()

        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(self._installed_binary().read_bytes(), self.binary_content)
        self.assertIn(f"currently resolves to {self.fake_bin / 'herdr'}", second.stdout)
        self.assertIn("installation directory to PATH", second.stdout)
        self.assertIn(str(self.install_dir), second.stdout)

    def test_darwin_arm64_selects_the_macos_aarch64_asset(self) -> None:
        target = "macos-aarch64"
        self._write_manifest(target=target)

        result = self._run(
            FAKE_ASSET_URL=self._asset_url(target),
            FAKE_UNAME_SYSTEM="Darwin",
            FAKE_UNAME_ARCH="arm64",
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"curl:{self._asset_url(target)}", self._command_log())
        self.assertEqual(self._installed_binary().read_bytes(), self.binary_content)

    def test_darwin_uses_the_portable_stat_path(self) -> None:
        real_stat = shutil.which("stat")
        if real_stat is None:
            self.fail("test host is missing stat")
        self._write_executable(
            "stat",
            f"""#!/bin/sh
if [ "$1" = "-c" ]; then
    exit 1
fi
[ "$1" = "-f" ] || exit 2
case "$2" in
    %u) exec {real_stat} -c %u "$3" ;;
    %Lp) exec {real_stat} -c %a "$3" ;;
    *) exit 3 ;;
esac
""",
        )

        result = self._run()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self._installed_binary().is_file())


if __name__ == "__main__":
    unittest.main()
