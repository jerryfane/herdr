#!/bin/sh
# Launch the pane fence end-to-end test in a throwaway Docker container.
# Usage: scripts/fence/run-in-container.sh <linux herdr binary>
#
# The container gets CAP_SYS_ADMIN and relaxed AppArmor/seccomp so the server can
# create mount namespaces. Those mounts live in the container's own namespace;
# this script also compares the host mount table (restricted to the container's
# paths) before and after.
set -eu
BIN=${1:?usage: run-in-container.sh <linux herdr binary>}
HERE=$(cd -- "$(dirname -- "$0")" && pwd)
IMAGE=${HERDR_FENCE_TEST_IMAGE:-debian:trixie}

before=$(mktemp); after=$(mktemp)
trap 'rm -f -- "$before" "$after"' EXIT
# Docker network namespaces of unrelated containers come and go; ignore them.
findmnt -R -n -o TARGET,SOURCE,FSTYPE,OPTIONS,PROPAGATION / | grep -v '/run/docker/netns/' | sort > "$before"

status=0
# SYS_PTRACE, DAC_READ_SEARCH and SYS_BOOT give the unfenced control run something to
# lose; SYS_BOOT in a container only affects its own PID namespace. SYS_MODULE is
# never granted.
docker run --rm --cap-add SYS_ADMIN --cap-add SYS_PTRACE --cap-add DAC_READ_SEARCH --cap-add SYS_BOOT \
  --security-opt apparmor=unconfined --security-opt seccomp=unconfined \
  -v "$(realpath -- "$BIN"):/usr/local/bin/herdr:ro" \
  -v "$HERE:/fence:ro" \
  "$IMAGE" sh -c 'apt-get -qq update >/dev/null && apt-get -qq install -y util-linux perl >/dev/null 2>&1; sh /fence/container-test.sh' || status=$?

findmnt -R -n -o TARGET,SOURCE,FSTYPE,OPTIONS,PROPAGATION / | grep -v '/run/docker/netns/' | sort > "$after"
if ! diff "$before" "$after" | grep -E '/fleet|/root/.config/herdr|fence' ; then
  echo "host mount table: no fence-related change"
else
  echo "FAIL host mount table changed"; status=1
fi
exit $status
