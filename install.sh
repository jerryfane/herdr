#!/bin/sh
# Install the herdr fork this app talks to.
#
# WHY THIS EXISTS RATHER THAN UPSTREAM'S INSTALLER: herdr.dev/install.sh installs
# UPSTREAM herdr, which does not have the `api-bridge` subcommand the herdrup app
# drives. Someone who runs the upstream one-liner gets a working herdr that the app
# cannot talk to, and the failure surfaces later as "the herdr on <host> is too old
# or isn't the fork" — a confusing error for a correct-looking install.
#
# Deliberately conservative: it builds from source in a directory it owns, installs
# ONE binary to ~/.local/bin, and touches nothing else. No sudo, no system paths, no
# shell-profile edits.
set -eu

REPO="${HERDR_REPO:-https://github.com/jerryfane/herdr}"
BRANCH="${HERDR_BRANCH:-master}"
SRC="${HERDR_SRC:-$HOME/.herdr-src}"
BIN_DIR="${HERDR_BIN_DIR:-$HOME/.local/bin}"

say() { printf '%s\n' "$*"; }
die() { printf 'install: %s\n' "$*" >&2; exit 1; }

# Check the toolchain FIRST. Without this the failure is a bare "cargo: not found"
# several steps in, after a clone has already been made.
command -v git >/dev/null 2>&1 || die "git is required. Install it, then run this again."
RUSTUP_HINT="curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
if ! command -v cargo >/dev/null 2>&1; then
    die "Rust is required to build herdr.
  Install it with:  $RUSTUP_HINT
  Then open a new terminal and run this again."
fi
# PRESENCE IS NOT ENOUGH, and this was measured rather than imagined: a distro cargo
# (Debian ships 1.75) passes `command -v` and then dies on `failed to parse lock file`,
# because this repo's Cargo.lock is version 4. That error names neither Rust nor the
# version, so it reads as a broken repository rather than an old toolchain.
#
# rustup is the happy path: the repo pins its toolchain in rust-toolchain.toml, so a
# rustup-managed cargo fetches the right version by itself and no check is needed.
if ! command -v rustup >/dev/null 2>&1; then
    cargo_ver=$(cargo --version 2>/dev/null | awk '{print $2}')
    cargo_major=${cargo_ver%%.*}
    cargo_rest=${cargo_ver#*.}
    cargo_minor=${cargo_rest%%.*}
    if [ "${cargo_major:-0}" -eq 1 ] && [ "${cargo_minor:-0}" -lt 78 ]; then
        die "cargo $cargo_ver is too old to read this project's lockfile (needs 1.78+).
  This is usually a cargo installed by your package manager.
  Install rustup instead, which picks up the version this project pins:
    $RUSTUP_HINT
  Then open a new terminal and run this again."
    fi
fi

say "Installing the herdr fork from $REPO ($BRANCH)"

if [ -d "$SRC/.git" ]; then
    say "Updating $SRC"
    git -C "$SRC" fetch --quiet origin "$BRANCH"
    # Reset rather than pull: this directory is ours, and a merge conflict here
    # would strand a first-time user inside git rather than installing anything.
    git -C "$SRC" reset --quiet --hard "origin/$BRANCH"
else
    say "Cloning into $SRC"
    git clone --quiet --branch "$BRANCH" "$REPO" "$SRC"
fi

say "Building (this takes a few minutes the first time)"
( cd "$SRC" && cargo build --release )

# install -D creates the parent directory, so no separate mkdir.
install -D -m 0755 "$SRC/target/release/herdr" "$BIN_DIR/herdr"
say "Installed $BIN_DIR/herdr"

# Say something USEFUL when the binary is installed but unreachable — otherwise the
# next instruction ("run herdr pair") fails with "command not found" and looks like
# the install failed.
if ! command -v herdr >/dev/null 2>&1; then
    say ""
    say "NOTE: $BIN_DIR is not on your PATH, so 'herdr' will not be found yet."
    say "Add it with:"
    say "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc && exec zsh"
fi

say ""
say "Next: run  herdr pair  and scan the code with the herdrup app."
