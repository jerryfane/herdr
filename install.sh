#!/bin/sh
# Install the prebuilt herdr fork used by the herdrup app.
#
# herdr.dev/install.sh installs upstream Herdr, which does not have this fork's
# `api-bridge` subcommand. This installer selects the latest published preview
# asset from the fork's checked-in manifest, verifies its SHA-256 digest, and
# installs only one binary under the invoking user's home directory.
set -eu
set -f
umask 077

DEFAULT_MANIFEST_URL="https://raw.githubusercontent.com/jerryfane/herdr/master/website/preview.json"
EXPECTED_RELEASE_ROOT="https://github.com/jerryfane/herdr/releases/download"

MANIFEST_URL="${HERDR_MANIFEST_URL:-$DEFAULT_MANIFEST_URL}"
BIN_DIR_REQUESTED="${HERDR_BIN_DIR:-$HOME/.local/bin}"

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

manifest_value() {
    metadata_key=$1
    awk -v wanted="$metadata_key" '
        index($0, wanted "=") == 1 {
            count += 1
            value = $0
            sub(/^[^=]*=/, "", value)
        }
        END {
            if (count != 1 || value == "") exit 1
            print value
        }
    ' "$METADATA_FILE"
}

case "$HOME" in
    /*) ;;
    *) die "HOME must be a non-empty absolute path." ;;
esac
[ "$HOME" != "/" ] || die "refusing to install with HOME set to /."
validate_home_path "$BIN_DIR_REQUESTED"

for required_command in awk chmod cp curl id mkdir mktemp mv rm stat uname; do
    require_command "$required_command"
done

case $(uname -s 2>/dev/null || :) in
    Linux) target_os=linux ;;
    Darwin) target_os=macos ;;
    *) die "this binary installer supports Linux and macOS only." ;;
esac
case $(uname -m 2>/dev/null || :) in
    x86_64|amd64) target_arch=x86_64 ;;
    aarch64|arm64) target_arch=aarch64 ;;
    *) die "this installer does not have a binary for this CPU architecture." ;;
esac
TARGET=$target_os-$target_arch
ASSET_NAME=herdr-$TARGET

INSTALL_UID=$(id -u 2>/dev/null) || die "could not determine the current user."
case "$INSTALL_UID" in
    ''|*[!0-9]*) die "id returned an invalid user identifier." ;;
esac
inspect_existing_home_path "$BIN_DIR_REQUESTED"

RUN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/herdr-fork-installer.XXXXXX") || die "could not create a private download directory."
case "$RUN_DIR" in
    /*/herdr-fork-installer.*) ;;
    *) die "mktemp returned an unsafe download directory." ;;
esac
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
        /*/herdr-fork-installer.*) rm -rf "$RUN_DIR" || : ;;
    esac
    exit "$cleanup_status"
}
trap cleanup 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

MANIFEST_FILE=$RUN_DIR/preview.json
METADATA_FILE=$RUN_DIR/asset.env
DOWNLOADED_BINARY=$RUN_DIR/herdr

say "Fetching the latest herdrup-compatible Herdr build"
curl -q --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 10 --max-time 30 \
    --max-filesize 5242880 \
    "$MANIFEST_URL" -o "$MANIFEST_FILE" || die "could not download the fork preview manifest."
[ -s "$MANIFEST_FILE" ] && [ ! -L "$MANIFEST_FILE" ] || die "the fork preview manifest is empty or unsafe."

BUILD_ID=$(awk -F '"' '
    /^  "build_id"[[:space:]]*:/ { print $4; count += 1 }
    END { if (count != 1) exit 1 }
' "$MANIFEST_FILE") || die "the fork preview manifest does not contain one current build_id."
case "$BUILD_ID" in
    ''|*[!A-Za-z0-9._-]*) die "the fork preview manifest contains an invalid build_id." ;;
esac

# Read only builds[build_id].assets[target]. The manifest also archives older
# builds with the same target names, so selecting the first matching target
# would silently install the wrong release.
awk -v wanted_build="$BUILD_ID" -v wanted_target="$TARGET" '
    function indentation(line, prefix) {
        prefix = line
        sub(/[^[:space:]].*$/, "", prefix)
        return length(prefix)
    }
    function trimmed(line) {
        sub(/^[[:space:]]*/, "", line)
        return line
    }
    function quoted_value(line, parts) {
        split(line, parts, "\"")
        return parts[4]
    }
    {
        indent = indentation($0)
        line = trimmed($0)

        if (indent == 2 && line ~ /^"builds"[[:space:]]*:/) {
            in_builds = 1
            next
        }
        if (in_builds && indent == 4 && line ~ /^"/) {
            split(line, key_parts, "\"")
            in_build = (key_parts[2] == wanted_build)
            in_assets = 0
            in_target = 0
            next
        }
        if (!in_build) next

        if (indent == 6 && line ~ /^"tag"[[:space:]]*:/) {
            print "tag=" quoted_value(line)
            next
        }
        if (indent == 6 && line ~ /^"assets"[[:space:]]*:/) {
            in_assets = 1
            next
        }
        if (in_assets && indent == 8 && line ~ /^"/) {
            split(line, key_parts, "\"")
            in_target = (key_parts[2] == wanted_target)
            next
        }
        if (!in_target) next
        if (indent == 10 && line ~ /^"url"[[:space:]]*:/) {
            print "url=" quoted_value(line)
        } else if (indent == 10 && line ~ /^"sha256"[[:space:]]*:/) {
            print "sha256=" quoted_value(line)
        }
    }
' "$MANIFEST_FILE" > "$METADATA_FILE" || die "could not parse the fork preview manifest."

TAG=$(manifest_value tag) || die "the current fork preview build is missing one release tag."
URL=$(manifest_value url) || die "the current fork preview build has no binary for $TARGET."
SHA256=$(manifest_value sha256) || die "the current fork preview build has no checksum for $TARGET."

case "$TAG" in
    preview-*) ;;
    *) die "the fork preview manifest contains an invalid release tag." ;;
esac
tag_suffix=${TAG#preview-}
[ -n "$tag_suffix" ] || die "the fork preview manifest contains an empty release tag."
case "$TAG" in
    *[!A-Za-z0-9._-]*) die "the fork preview manifest contains an invalid release tag." ;;
esac
EXPECTED_URL=$EXPECTED_RELEASE_ROOT/$TAG/$ASSET_NAME
[ "$URL" = "$EXPECTED_URL" ] || die "the fork preview asset URL does not resolve to jerryfane/herdr: $URL"
case "$SHA256" in
    *[!0-9A-Fa-f]*) die "the fork preview asset checksum is not hexadecimal." ;;
esac
[ "${#SHA256}" -eq 64 ] || die "the fork preview asset checksum is not a SHA-256 digest."
SHA256=$(printf '%s\n' "$SHA256" | awk '{ print tolower($0) }')

if command -v sha256sum >/dev/null 2>&1; then
    SHA256_TOOL=sha256sum
elif command -v shasum >/dev/null 2>&1; then
    SHA256_TOOL=shasum
elif command -v openssl >/dev/null 2>&1; then
    SHA256_TOOL=openssl
else
    die "SHA-256 verification requires sha256sum, shasum, or openssl."
fi

say "Downloading $TAG for $TARGET"
curl -q --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 10 --max-time 180 \
    --max-filesize 104857600 \
    "$URL" -o "$DOWNLOADED_BINARY" || die "could not download $ASSET_NAME; the installed binary was not changed."
[ -s "$DOWNLOADED_BINARY" ] && [ ! -L "$DOWNLOADED_BINARY" ] || die "the downloaded Herdr binary is empty or unsafe."

case "$SHA256_TOOL" in
    sha256sum) ACTUAL_SHA256=$(sha256sum < "$DOWNLOADED_BINARY" | awk '{ print $1 }') ;;
    shasum) ACTUAL_SHA256=$(shasum -a 256 < "$DOWNLOADED_BINARY" | awk '{ print $1 }') ;;
    openssl) ACTUAL_SHA256=$(openssl dgst -sha256 < "$DOWNLOADED_BINARY" | awk '{ print $NF }') ;;
esac
[ "$ACTUAL_SHA256" = "$SHA256" ] || die "downloaded Herdr checksum did not match; the installed binary was not changed."

prepare_home_directory "$BIN_DIR_REQUESTED"
BIN_DIR=$PREPARED_DIR
destination=$BIN_DIR/herdr
[ ! -L "$destination" ] || die "$destination is a symlink; refusing to replace it."
[ ! -d "$destination" ] || die "$destination is a directory; refusing to replace it."

# Create beside the destination so the final rename stays on one filesystem.
# A failed copy or chmod leaves an existing binary untouched; a successful mv
# atomically replaces it.
TEMP_BINARY=$(mktemp "$BIN_DIR/.herdr-install.XXXXXX") || die "could not create an installation staging file in $BIN_DIR."
cp "$DOWNLOADED_BINARY" "$TEMP_BINARY" || die "could not stage the new Herdr binary; the installed binary was not changed."
chmod 0755 "$TEMP_BINARY" || die "could not make the staged Herdr binary executable; the installed binary was not changed."
mv -f "$TEMP_BINARY" "$destination" || die "could not activate the new Herdr binary; the installed binary was not changed."
TEMP_BINARY=
say "Installed $destination from $TAG"

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
    say "You can also run it directly:"
    say "  $destination pair"
else
    say ""
    say "Next: run  herdr pair  and scan the code with the herdrup app."
fi
