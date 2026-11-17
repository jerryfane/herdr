#!/usr/bin/env bash
# The one definition of a preview build's identity, shared by preview.yml
# (which publishes it in the manifest) and build-artifacts-manual.yml (which
# embeds it in the binary). The in-app updater settles a restart only when the
# two agree, so neither may compute it on its own.
#
# Prints, for the checked-out HEAD (or the commit given as $1):
#   HERDR_BUILD_COMMIT=<40-char sha>
#   HERDR_BUILD_ID=<commit date, YYYY-MM-DD>-<12-char sha>
set -euo pipefail

rev="${1:-HEAD}"
commit="$(git rev-parse --verify "$rev^{commit}")"
day="$(git show -s --format=%cs "$commit")"
short_sha="$(git rev-parse --short=12 "$commit")"
echo "HERDR_BUILD_COMMIT=$commit"
echo "HERDR_BUILD_ID=$day-$short_sha"
