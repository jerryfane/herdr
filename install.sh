#!/bin/sh
# Install the herdr fork used by the herdrup app.
#
# herdr.dev/install.sh installs upstream Herdr, which does not have this fork's
# `api-bridge` subcommand. This installer builds an authenticated fork revision
# and installs only one binary under the invoking user's home directory.
set -eu
set -f
umask 077

DEFAULT_REPO="https://github.com/jerryfane/herdr.git"
# Keep this immutable. Updating the installed source is an explicit reviewed
# change to this script, not an implicit consequence of a moving branch.
DEFAULT_REV="00b5cc8723dc3887b75b3e03df0cdadfdd554e1b"
TOOLCHAIN="1.96.1"
STATE_MARKER="herdr-fork-installer-v1"

REPO="${HERDR_REPO:-$DEFAULT_REPO}"
REV="${HERDR_REV:-$DEFAULT_REV}"
BIN_DIR_REQUESTED="${HERDR_BIN_DIR:-$HOME/.local/bin}"
STATE_DIR_REQUESTED="$HOME/.cache/herdr-fork-installer"

# Persistent build state is confined to STATE_DIR/{cargo,rustup,zig}. Each run's
# authenticated checkout and target directory live under STATE_DIR/run.* and are
# removed on exit. The only other write is the final binary under BIN_DIR.
# Compiling trusted, pinned source still executes its build scripts as the user;
# this is a constrained layout, not an operating-system sandbox.

say() { printf '%s\n' "$*"; }
die() { printf 'install: %s\n' "$*" >&2; exit 1; }

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "$1 is required. Install it, then run this again."
}

stat_owner() {
    if stat -c '%u' "$1" >/dev/null 2>&1; then
        stat -c '%u' "$1"
    else
        stat -f '%u' "$1"
    fi
}

stat_mode() {
    if stat -c '%a' "$1" >/dev/null 2>&1; then
        stat -c '%a' "$1"
    else
        stat -f '%Lp' "$1"
    fi
}

require_safe_directory() {
    safe_dir=$1
    [ -d "$safe_dir" ] && [ ! -L "$safe_dir" ] || die "$safe_dir must be a real directory, not a symlink."

    safe_owner=$(stat_owner "$safe_dir") || die "could not determine the owner of $safe_dir."
    [ "$safe_owner" = "$INSTALL_UID" ] || die "$safe_dir is not owned by the current user."

    safe_mode=$(stat_mode "$safe_dir") || die "could not determine the permissions of $safe_dir."
    case "$safe_mode" in
        *[2367]?|*?[2367]) die "$safe_dir must not be writable by group or other users." ;;
    esac
}

validate_home_path() {
    validated_path=$1
    case "$validated_path" in
        "$HOME"/*) validated_relative=${validated_path#"$HOME"/} ;;
        *) die "$validated_path must be an absolute path below HOME ($HOME)." ;;
    esac
    [ -n "$validated_relative" ] || die "refusing to use HOME itself as an install directory."
    case "/$validated_relative/" in
        *"//"*|*"/./"*|*"/../"*) die "$validated_path contains an unsafe path component." ;;
    esac
}

inspect_existing_home_path() {
    inspected_dir=$1
    validate_home_path "$inspected_dir"
    inspected_relative=$validated_relative
    inspected_current=$HOME
    require_safe_directory "$inspected_current"

    saved_ifs=$IFS
    IFS=/
    set -- $inspected_relative
    IFS=$saved_ifs
    for inspected_component do
        inspected_next=$inspected_current/$inspected_component
        if [ -L "$inspected_next" ]; then
            die "$inspected_next is a symlink; refusing to follow it."
        elif [ -e "$inspected_next" ]; then
            require_safe_directory "$inspected_next"
        else
            return 0
        fi
        inspected_current=$inspected_next
    done
}

# Resolve and create a directory component by component. This rejects '..' and
# symlink redirections before a write can escape the invoking user's home.
prepare_home_directory() {
    requested_dir=$1
    validate_home_path "$requested_dir"
    relative_dir=$validated_relative

    prepared_dir=$HOME
    require_safe_directory "$prepared_dir"

    saved_ifs=$IFS
    IFS=/
    set -- $relative_dir
    IFS=$saved_ifs
    for path_component do
        [ -n "$path_component" ] || die "$requested_dir contains an empty path component."
        next_dir=$prepared_dir/$path_component
        if [ -L "$next_dir" ]; then
            die "$next_dir is a symlink; refusing to follow it."
        elif [ -e "$next_dir" ]; then
            require_safe_directory "$next_dir"
        else
            mkdir "$next_dir" || die "could not create $next_dir."
            require_safe_directory "$next_dir"
        fi
        prepared_dir=$next_dir
    done
    PREPARED_DIR=$prepared_dir
}

prepare_state_subdirectory() {
    state_subdir=$1
    if [ -L "$state_subdir" ]; then
        die "$state_subdir is a symlink; refusing to use it."
    elif [ -e "$state_subdir" ]; then
        require_safe_directory "$state_subdir"
    else
        mkdir "$state_subdir" || die "could not create $state_subdir."
        require_safe_directory "$state_subdir"
    fi
}

require_version_at_least() {
    version_label=$1
    actual_version=$2
    required_major=$3
    required_minor=$4
    required_patch=$5
    version_core=${actual_version%%[-+]*}

    saved_ifs=$IFS
    IFS=.
    set -- $version_core
    IFS=$saved_ifs
    [ "$#" -eq 3 ] || die "$version_label returned an unrecognized version: $actual_version"
    actual_major=$1
    actual_minor=$2
    actual_patch=$3
    case "$actual_major$actual_minor$actual_patch" in
        ''|*[!0-9]*) die "$version_label returned an unrecognized version: $actual_version" ;;
    esac

    if [ "$actual_major" -lt "$required_major" ] ||
       { [ "$actual_major" -eq "$required_major" ] && [ "$actual_minor" -lt "$required_minor" ]; } ||
       { [ "$actual_major" -eq "$required_major" ] && [ "$actual_minor" -eq "$required_minor" ] && [ "$actual_patch" -lt "$required_patch" ]; }; then
        die "$version_label $actual_version is too old; version $required_major.$required_minor.$required_patch or newer is required."
    fi
}

case "$HOME" in
    /*) ;;
    *) die "HOME must be a non-empty absolute path." ;;
esac
[ "$HOME" != "/" ] || die "refusing to install with HOME set to /."
validate_home_path "$BIN_DIR_REQUESTED"

case "$REV" in
    ''|*[!0-9a-f]*) die "HERDR_REV must be an exact lowercase 40-character Git commit." ;;
esac
[ "${#REV}" -eq 40 ] || die "HERDR_REV must be an exact lowercase 40-character Git commit."

for required_command in git cargo zig cat chmod cp id mkdir mktemp mv rm stat uname; do
    require_command "$required_command"
done

case $(uname -s 2>/dev/null || :) in
    Linux|Darwin) ;;
    *) die "this source installer supports Linux and macOS only." ;;
esac

INSTALL_UID=$(id -u 2>/dev/null) || die "could not determine the current user."
case "$INSTALL_UID" in
    ''|*[!0-9]*) die "id returned an invalid user identifier." ;;
esac
inspect_existing_home_path "$BIN_DIR_REQUESTED"

zig_version=$(zig version 2>/dev/null) || die "could not read the Zig version."
zig_core=${zig_version%%[-+]*}
saved_ifs=$IFS
IFS=.
set -- $zig_core
IFS=$saved_ifs
if [ "$#" -ne 3 ] || [ "$1" != 0 ] || [ "$2" != 15 ]; then
    die "Zig $zig_version is unsupported; install Zig 0.15.2 or newer in the 0.15 series."
fi
case "$3" in
    ''|*[!0-9]*) die "Zig returned an unrecognized version: $zig_version" ;;
esac
[ "$3" -ge 2 ] || die "Zig $zig_version is too old; install Zig 0.15.2 or newer in the 0.15 series."

state_existed=0
if [ -e "$STATE_DIR_REQUESTED" ] || [ -L "$STATE_DIR_REQUESTED" ]; then
    state_existed=1
fi
prepare_home_directory "$STATE_DIR_REQUESTED"
STATE_DIR=$PREPARED_DIR
marker_file=$STATE_DIR/.owner
if [ "$state_existed" -eq 1 ]; then
    [ -f "$marker_file" ] && [ ! -L "$marker_file" ] || die "$STATE_DIR was not created by this installer; move it aside and try again."
    marker_value=$(cat "$marker_file") || die "could not read $marker_file."
    [ "$marker_value" = "$STATE_MARKER" ] || die "$STATE_DIR has an invalid ownership marker; move it aside and try again."
else
    printf '%s\n' "$STATE_MARKER" > "$marker_file" || die "could not mark $STATE_DIR as installer-owned."
fi

prepare_state_subdirectory "$STATE_DIR/cargo"
prepare_state_subdirectory "$STATE_DIR/rustup"
prepare_state_subdirectory "$STATE_DIR/zig"
export CARGO_HOME=$STATE_DIR/cargo
export RUSTUP_HOME=$STATE_DIR/rustup
export ZIG_GLOBAL_CACHE_DIR=$STATE_DIR/zig
unset CARGO_TARGET_DIR RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
unset RUSTUP_DIST_SERVER RUSTUP_UPDATE_ROOT RUSTUP_TOOLCHAIN ZIG_LOCAL_CACHE_DIR

USE_RUSTUP=0
if command -v rustup >/dev/null 2>&1; then
    USE_RUSTUP=1
    say "Preparing Rust $TOOLCHAIN"
    rustup toolchain install "$TOOLCHAIN" --profile minimal >/dev/null || die "rustup could not install Rust $TOOLCHAIN."
    cargo_output=$(rustup run "$TOOLCHAIN" cargo --version 2>/dev/null) || die "Rust $TOOLCHAIN does not provide a working Cargo."
    rustc_output=$(rustup run "$TOOLCHAIN" rustc --version 2>/dev/null) || die "Rust $TOOLCHAIN does not provide a working rustc."
else
    require_command rustc
    cargo_output=$(cargo --version 2>/dev/null) || die "could not read the Cargo version."
    rustc_output=$(rustc --version 2>/dev/null) || die "could not read the rustc version."
fi
case "$cargo_output" in
    cargo\ *) cargo_version=${cargo_output#cargo }; cargo_version=${cargo_version%% *} ;;
    *) die "Cargo returned an unrecognized version: $cargo_output" ;;
esac
case "$rustc_output" in
    rustc\ *) rustc_version=${rustc_output#rustc }; rustc_version=${rustc_version%% *} ;;
    *) die "rustc returned an unrecognized version: $rustc_output" ;;
esac
require_version_at_least Cargo "$cargo_version" 1 96 1
require_version_at_least rustc "$rustc_version" 1 96 1

RUN_DIR=$(mktemp -d "$STATE_DIR/run.XXXXXX") || die "could not create a private build directory in $STATE_DIR."
TEMP_BINARY=
cleanup() {
    cleanup_status=$?
    trap - 0 HUP INT TERM
    if [ -n "$TEMP_BINARY" ]; then
        case "$TEMP_BINARY" in
            "$BIN_DIR"/.herdr-install.*) rm -f "$TEMP_BINARY" || : ;;
        esac
    fi
    case "$RUN_DIR" in
        "$STATE_DIR"/run.*) rm -rf "$RUN_DIR" || : ;;
    esac
    exit "$cleanup_status"
}
trap cleanup 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

SRC=$RUN_DIR/source
export CARGO_TARGET_DIR=$RUN_DIR/target

# Ignore Git environment redirections. The remote may be overridden, but the
# exact source object must still match REV before any source code is compiled.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_REPLACE_REF_BASE GIT_CONFIG_COUNT
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null
export GIT_TERMINAL_PROMPT=0

say "Fetching authenticated source $REV"
mkdir "$SRC" || die "could not create the source directory."
git -C "$SRC" init --quiet || die "could not initialize the private source checkout."
git -C "$SRC" remote add origin "$REPO" || die "could not configure the source remote."
git -C "$SRC" fetch --quiet --depth 1 origin "$REV" || die "could not fetch source revision $REV from $REPO."
fetched_rev=$(git -C "$SRC" rev-parse --verify 'FETCH_HEAD^{commit}' 2>/dev/null) || die "the fetched source is not a commit."
[ "$fetched_rev" = "$REV" ] || die "source verification failed: expected $REV but fetched $fetched_rev."
git -C "$SRC" checkout --quiet --detach "$REV" || die "could not check out verified source revision $REV."
checked_out_rev=$(git -C "$SRC" rev-parse --verify 'HEAD^{commit}' 2>/dev/null) || die "could not verify the checked-out source."
[ "$checked_out_rev" = "$REV" ] || die "checked-out source does not match verified revision $REV."

say "Building (this takes a few minutes the first time)"
if [ "$USE_RUSTUP" -eq 1 ]; then
    (cd "$SRC" && rustup run "$TOOLCHAIN" cargo build --release --locked) || die "the Herdr build failed; the installed binary was not changed."
else
    (cd "$SRC" && cargo build --release --locked) || die "the Herdr build failed; the installed binary was not changed."
fi

built_binary=$CARGO_TARGET_DIR/release/herdr
[ -f "$built_binary" ] && [ ! -L "$built_binary" ] || die "the build did not produce a regular Herdr binary."

prepare_home_directory "$BIN_DIR_REQUESTED"
BIN_DIR=$PREPARED_DIR
destination=$BIN_DIR/herdr
[ ! -L "$destination" ] || die "$destination is a symlink; refusing to replace it."
[ ! -d "$destination" ] || die "$destination is a directory; refusing to replace it."

# Create beside the destination so the final rename stays on one filesystem.
# A failed copy or chmod leaves an existing binary untouched; a successful mv
# atomically replaces it.
TEMP_BINARY=$(mktemp "$BIN_DIR/.herdr-install.XXXXXX") || die "could not create an installation staging file in $BIN_DIR."
cp "$built_binary" "$TEMP_BINARY" || die "could not stage the new Herdr binary; the installed binary was not changed."
chmod 0755 "$TEMP_BINARY" || die "could not make the staged Herdr binary executable; the installed binary was not changed."
mv -f "$TEMP_BINARY" "$destination" || die "could not activate the new Herdr binary; the installed binary was not changed."
TEMP_BINARY=
say "Installed $destination from verified revision $REV"

hash -r 2>/dev/null || :
resolved_herdr=$(command -v herdr 2>/dev/null || :)
if [ "$resolved_herdr" != "$destination" ]; then
    say ""
    if [ -n "$resolved_herdr" ]; then
        say "NOTE: 'herdr' currently resolves to $resolved_herdr, not $destination."
    else
        say "NOTE: $BIN_DIR is not on PATH, so 'herdr' will not be found yet."
    fi
    say "Add this installation directory to PATH in your shell configuration:"
    say "  $BIN_DIR"
    say "Then run 'herdr pair'."
    say "You can also invoke the installed file directly with the 'pair' argument:"
    say "  $destination"
else
    say ""
    say "Next: run  herdr pair  and scan the code with the herdrup app."
fi
