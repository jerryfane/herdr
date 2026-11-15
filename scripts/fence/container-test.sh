#!/bin/sh
# End-to-end pane fence test. Runs a real herdr server inside a THROWAWAY container,
# opens a fenced pane, runs scripts/fence/checks.sh in it and unfenced (positive
# control), compares, and checks the container's root mount table is unchanged.
#
# Never run this on a host: it refuses outside a container. Start it with
#   scripts/fence/run-in-container.sh <path-to-linux-herdr-binary>
set -eu
[ -f /.dockerenv ] || { echo "refusing: not inside a throwaway container"; exit 2; }

HERDR=/usr/local/bin/herdr
CHECKS=/fence/checks.sh
OUT=/tmp/fence-out
mkdir -p "$OUT"

# Fixture: protected tree with a carve-out, a spare dir, herdr config.
mkdir -p /fleet/protected/sub /fleet/protected/db /fleet/protected/spare
echo cfg > /fleet/protected/config.toml
echo data > /fleet/protected/db/data.db
echo keep > /fleet/protected/sub/keep
export HOME=/root XDG_CONFIG_HOME=/root/.config
CFG_DIR=$XDG_CONFIG_HOME/herdr
mkdir -p "$CFG_DIR"
cat > "$CFG_DIR/config.toml" <<'EOF'
[fence]
enabled = true
deny = ["/fleet/protected"]
allow = ["/fleet/protected/db", "/fleet/protected/spare"]
EOF
# A system bus stand-in so the mask has something to hide.
mkdir -p /run/dbus
perl -MIO::Socket::UNIX -e '
  my $s = IO::Socket::UNIX->new(Type=>SOCK_STREAM(), Local=>"/run/dbus/system_bus_socket", Listen=>5) or die $!;
  while (my $c = $s->accept) { close $c }' &

findmnt -R -n -o TARGET,SOURCE,FSTYPE,OPTIONS,PROPAGATION / | sort > "$OUT/mounts-before"

"$HERDR" server > "$OUT/server.log" 2>&1 &
SERVER=$!
i=0
until "$HERDR" pane list >/dev/null 2>&1; do
  i=$((i + 1)); [ $i -lt 100 ] || { cat "$OUT/server.log"; echo "server did not start"; exit 1; }
  sleep 0.1
done

pane_ids() { "$HERDR" pane list | grep -o '"pane_id":"[^"]*"' | cut -d'"' -f4; }
FIRST=$(pane_ids | head -n1)
[ -n "$FIRST" ] || { echo "no pane"; exit 1; }
# Fresh pane started under the fence (the first pane may predate nothing, but split makes the case explicit).
"$HERDR" pane split --direction right --cwd /fleet/protected "$FIRST" >/dev/null
PANE=$(pane_ids | grep -vx "$FIRST" | head -n1)
[ -n "$PANE" ] || { echo "split pane missing"; exit 1; }

"$HERDR" pane run "$PANE" "sh $CHECKS > $OUT/fenced.txt 2>&1; echo cwd-rel > ./cwd-rel 2>/dev/null; echo done > $OUT/fenced.done" >/dev/null
i=0
until [ -f "$OUT/fenced.done" ]; do
  i=$((i + 1)); [ $i -lt 300 ] || { "$HERDR" pane read "$PANE" --source recent --lines 40 || true; echo "fenced run timed out"; exit 1; }
  sleep 0.1
done

kill "$SERVER"; wait "$SERVER" 2>/dev/null || true
sleep 0.3
findmnt -R -n -o TARGET,SOURCE,FSTYPE,OPTIONS,PROPAGATION / | sort > "$OUT/mounts-after"

# Positive control: same checks, no fence, after the server is gone. The mount table
# was already compared, so give remount/umount a real bind to act on, as in the pane.
mount --bind /fleet/protected /fleet/protected
sh "$CHECKS" > "$OUT/control.txt" 2>&1

echo "== fenced vs unfenced"
paste -d' ' "$OUT/fenced.txt" "$OUT/control.txt" | awk '{printf "%-24s fenced=%-8s unfenced=%s\n", $1, $2, $4}'

fail=0
expect() { # expect <check> <fenced result> <unfenced result>
  got_f=$(awk -v n="$1" '$1==n{print $2}' "$OUT/fenced.txt")
  got_c=$(awk -v n="$1" '$1==n{print $2}' "$OUT/control.txt")
  if [ "$got_f" != "$2" ] || [ "$got_c" != "$3" ]; then
    echo "FAIL $1: fenced=$got_f (want $2) unfenced=$got_c (want $3)"; fail=1
  fi
}
for c in write_denied overwrite_denied rm_denied_tree rm_herdr_config rmdir_carveout rename_ancestor \
         remount_denied_rw umount_denied nsenter_init write_via_proc_root read_init_environ mknod_block \
         connect_masked_socket cap_sys_admin cap_sys_boot cap_sys_ptrace cap_mknod \
         cap_dac_read_search mount_tmpfs; do
  expect "$c" blocked ok
done
for c in write_carveout write_outside_deny rename_across_dirs; do
  expect "$c" ok ok
done
# userns: blocked in the pane; in the control it depends on the host's AppArmor userns policy.
expect_fenced() { got=$(awk -v n="$1" '$1==n{print $2}' "$OUT/fenced.txt"); [ "$got" = "$2" ] || { echo "FAIL $1: fenced=$got (want $2)"; fail=1; }; }
expect_fenced userns_write_denied blocked
expect_fenced herdr_cli_works ok
# CAP_SYS_MODULE is not granted to the container (it would reach the host kernel), so
# there is no unfenced control for it; the fence must still not hold it.
expect_fenced cap_sys_module blocked
grep -qx "fence_env 1" "$OUT/fenced.txt" || { echo "FAIL fenced pane has no HERDR_FENCE"; fail=1; }
[ -e /fleet/protected/cwd-rel ] && { echo "FAIL relative write via the inherited cwd landed in the denied dir"; fail=1; }
[ -f /fleet/protected/sub/keep ] || echo "note: control run removed the fixture as expected"

if ! diff "$OUT/mounts-before" "$OUT/mounts-after"; then
  echo "FAIL container root mount table changed"; fail=1
fi
[ $fail -eq 0 ] && echo "PASS pane fence end-to-end"
exit $fail
