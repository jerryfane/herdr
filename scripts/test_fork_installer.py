from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = REPO_ROOT / "install.sh"
EXPECTED_REV = "00b5cc8723dc3887b75b3e03df0cdadfdd554e1b"
REQUIRED_COMMANDS = ("cat", "chmod", "cp", "id", "mkdir", "mktemp", "mv", "rm", "stat")


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

        for command in REQUIRED_COMMANDS:
            path = shutil.which(command)
            if path is None:
                self.fail(f"test host is missing required command: {command}")
            (self.fake_bin / command).symlink_to(path)

        self._write_executable(
            "uname",
            """#!/bin/sh
[ "$1" = "-s" ] || exit 2
printf '%s\n' "${FAKE_UNAME:-Linux}"
""",
        )
        self._write_executable(
            "zig",
            """#!/bin/sh
[ "$1" = "version" ] || exit 2
printf '%s\n' "${FAKE_ZIG_VERSION:-0.15.2}"
""",
        )
        self._write_executable(
            "rustc",
            """#!/bin/sh
printf '%s\n' "rustc ${FAKE_RUST_VERSION:-1.96.1} (fake)"
""",
        )
        self._write_executable(
            "cargo",
            """#!/bin/sh
printf 'cargo:%s:%s\n' "${CARGO_TARGET_DIR:-unset}" "$*" >> "$FAKE_LOG"
if [ "$1" = "--version" ]; then
    printf '%s\n' "cargo ${FAKE_RUST_VERSION:-1.96.1} (fake)"
    exit 0
fi
[ "$1" = "build" ] || exit 2
[ "${FAKE_CARGO_FAIL:-0}" != 1 ] || exit 17
mkdir -p "$CARGO_TARGET_DIR/release"
printf '%s\n' "${FAKE_BINARY_CONTENT:-new-herdr}" > "$CARGO_TARGET_DIR/release/herdr"
""",
        )
        self._write_executable(
            "git",
            """#!/bin/sh
printf 'git:%s\n' "$*" >> "$FAKE_LOG"
git_dir=
if [ "$1" = "-C" ]; then
    git_dir=$2
    shift 2
fi
case "$1" in
    init)
        mkdir "$git_dir/.git"
        ;;
    remote|fetch|checkout)
        ;;
    rev-parse)
        case "$3" in
            FETCH_HEAD*) printf '%s\n' "${FAKE_FETCHED_REV:-$FAKE_EXPECTED_REV}" ;;
            HEAD*) printf '%s\n' "${FAKE_CHECKED_OUT_REV:-$FAKE_EXPECTED_REV}" ;;
            *) exit 3 ;;
        esac
        ;;
    *) exit 4 ;;
esac
""",
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

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
            "FAKE_EXPECTED_REV": EXPECTED_REV,
            "FAKE_LOG": str(self.log),
            "HERDR_BIN_DIR": str(self.install_dir),
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

    def _state_dir(self) -> Path:
        return self.home / ".cache" / "herdr-fork-installer"

    def _command_log(self) -> str:
        return self.log.read_text(encoding="utf-8") if self.log.exists() else ""

    def test_fetches_exact_revision_and_uses_constrained_build_paths(self) -> None:
        outside_target = self.root / "attacker-selected-target"
        result = self._run(
            include_install_dir_on_path=True,
            CARGO_TARGET_DIR=str(outside_target),
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self._installed_binary().read_text(encoding="utf-8"), "new-herdr\n")
        self.assertFalse(outside_target.exists())
        log = self._command_log()
        self.assertIn(f"fetch --quiet --depth 1 origin {EXPECTED_REV}", log)
        self.assertIn("build --release --locked", log)
        self.assertIn(str(self._state_dir() / "run."), log)
        self.assertNotIn("reset", log)
        self.assertFalse(list(self._state_dir().glob("run.*")))

    def test_source_mismatch_fails_before_build_and_preserves_binary(self) -> None:
        self.install_dir.mkdir(parents=True)
        self._installed_binary().write_text("working-herdr\n", encoding="utf-8")

        result = self._run(FAKE_FETCHED_REV="f" * 40)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source verification failed", result.stderr)
        self.assertEqual(self._installed_binary().read_text(encoding="utf-8"), "working-herdr\n")
        self.assertNotIn("build --release", self._command_log())

    def test_failed_build_does_not_replace_existing_binary(self) -> None:
        self.install_dir.mkdir(parents=True)
        self._installed_binary().write_text("working-herdr\n", encoding="utf-8")

        result = self._run(FAKE_CARGO_FAIL="1")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("installed binary was not changed", result.stderr)
        self.assertEqual(self._installed_binary().read_text(encoding="utf-8"), "working-herdr\n")
        self.assertFalse(list(self.install_dir.glob(".herdr-install.*")))

    def test_failed_atomic_promotion_preserves_existing_binary(self) -> None:
        self.install_dir.mkdir(parents=True)
        self._installed_binary().write_text("working-herdr\n", encoding="utf-8")
        self._write_executable("mv", "#!/bin/sh\nexit 19\n")

        result = self._run()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("could not activate", result.stderr)
        self.assertEqual(self._installed_binary().read_text(encoding="utf-8"), "working-herdr\n")
        self.assertFalse(list(self.install_dir.glob(".herdr-install.*")))

    def test_existing_unmarked_state_directory_is_refused(self) -> None:
        self._state_dir().mkdir(parents=True)

        result = self._run()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("was not created by this installer", result.stderr)
        self.assertEqual(self._command_log(), "")

    def test_unsupported_zig_fails_before_any_installer_state_is_created(self) -> None:
        result = self._run(FAKE_ZIG_VERSION="0.16.0")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Zig 0.16.0 is unsupported", result.stderr)
        self.assertFalse(self._state_dir().exists())
        self.assertEqual(self._command_log(), "")

    def test_install_directory_must_stay_below_home(self) -> None:
        outside_bin = self.root / "outside-home" / "bin"

        result = self._run(HERDR_BIN_DIR=str(outside_bin))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be an absolute path below HOME", result.stderr)
        self.assertFalse(self._state_dir().exists())
        self.assertFalse(outside_bin.exists())

    def test_symlinked_install_directory_is_refused_before_build(self) -> None:
        outside_dir = self.root / "outside-home"
        outside_dir.mkdir()
        (self.home / "linked").symlink_to(outside_dir, target_is_directory=True)

        result = self._run(HERDR_BIN_DIR=str(self.home / "linked" / "bin"))

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is a symlink; refusing to follow it", result.stderr)
        self.assertFalse(self._state_dir().exists())
        self.assertFalse((outside_dir / "bin").exists())
        self.assertEqual(self._command_log(), "")

    def test_repeat_run_is_idempotent_and_wrong_path_binary_is_reported(self) -> None:
        self._write_executable("herdr", "#!/bin/sh\nexit 0\n")
        first = self._run(FAKE_BINARY_CONTENT="first-build")
        second = self._run(FAKE_BINARY_CONTENT="second-build")

        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(self._installed_binary().read_text(encoding="utf-8"), "second-build\n")
        self.assertIn(f"currently resolves to {self.fake_bin / 'herdr'}", second.stdout)
        self.assertIn(f"installation directory to PATH", second.stdout)
        self.assertIn(str(self.install_dir), second.stdout)

    def test_rustup_path_uses_the_pinned_toolchain_and_private_homes(self) -> None:
        self._write_executable(
            "rustup",
            """#!/bin/sh
printf 'rustup:%s:%s:%s\n' "$CARGO_HOME" "$RUSTUP_HOME" "$*" >> "$FAKE_LOG"
case "$1" in
    toolchain) exit 0 ;;
    run)
        [ "$2" = "1.96.1" ] || exit 2
        command=$3
        shift 3
        exec "$command" "$@"
        ;;
    *) exit 3 ;;
esac
""",
        )

        result = self._run()

        self.assertEqual(result.returncode, 0, result.stderr)
        log = self._command_log()
        self.assertIn("toolchain install 1.96.1 --profile minimal", log)
        self.assertIn("run 1.96.1 cargo build --release --locked", log)
        self.assertIn(str(self._state_dir() / "cargo"), log)
        self.assertIn(str(self._state_dir() / "rustup"), log)

    def test_darwin_uses_the_portable_stat_and_install_path(self) -> None:
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

        result = self._run(FAKE_UNAME="Darwin")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self._installed_binary().is_file())


if __name__ == "__main__":
    unittest.main()
