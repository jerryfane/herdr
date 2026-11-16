#!/bin/sh
# Pane-fence back-door checks. Run by scripts/fence/container-test.sh once inside a
# fenced pane and once unfenced as the positive control. Prints one line per check:
# "<name> ok" when the action succeeded, "<name> blocked" when it failed.
# Only touches the fixture created by container-test.sh. Never run on a host.
set -u
[ -f /.dockerenv ] || { echo "refusing: not inside a throwaway container"; exit 2; }

F=/fleet
attempt() { # attempt <name> <cmd...>
  name=$1; shift
  if "$@" >/dev/null 2>&1; then echo "$name ok"; else echo "$name blocked"; fi
}
cap_bit() { # exit 0 when capability $1 is in the bounding set
  bnd=$(awk '/^CapBnd:/{print $2}' /proc/self/status)
  [ $(( (0x$bnd >> $1) & 1 )) -eq 1 ]
}

attempt write_denied          sh -c "echo x > $F/protected/new"
attempt overwrite_denied      sh -c "echo x > $F/protected/config.toml"
attempt rm_denied_tree        rm -rf "$F/protected/sub"
attempt write_carveout        sh -c "echo y >> $F/protected/db/data.db"
attempt rmdir_carveout        rmdir "$F/protected/spare"
attempt rename_ancestor       sh -c "mv $F $F.moved && mv $F.moved $F"
attempt write_outside_deny    sh -c "echo ok > /tmp/fence-free && rm /tmp/fence-free"
attempt rename_across_dirs    sh -c "mkdir -p /tmp/ra /tmp/rb && touch /tmp/ra/f && mv /tmp/ra/f /tmp/rb/f && rm -r /tmp/ra /tmp/rb"
attempt mount_tmpfs           sh -c "mkdir -p /tmp/fence-mnt && mount -t tmpfs t /tmp/fence-mnt && umount /tmp/fence-mnt"
attempt remount_denied_rw     mount -o remount,bind,rw "$F/protected"
attempt umount_denied         umount -l "$F/protected"
attempt nsenter_init          nsenter -t 1 -m true
attempt write_via_proc_root   sh -c "echo x > /proc/1/root$F/protected/via-proc && rm /proc/1/root$F/protected/via-proc"
attempt read_init_environ     cat /proc/1/environ
attempt mknod_block           sh -c "mknod /tmp/fence-blk b 7 200 && rm /tmp/fence-blk"
attempt userns_write_denied   unshare -Urm sh -c "echo x > $F/protected/userns && rm $F/protected/userns"
attempt connect_masked_socket perl -MIO::Socket::UNIX -e 'IO::Socket::UNIX->new(Type=>SOCK_STREAM(),Peer=>"/run/dbus/system_bus_socket") or exit 1'
attempt herdr_cli_works       herdr pane list
attempt cap_sys_admin         cap_bit 21
attempt cap_sys_module        cap_bit 16
attempt cap_sys_boot          cap_bit 22
attempt cap_sys_ptrace        cap_bit 19
attempt cap_mknod             cap_bit 27
attempt cap_dac_read_search   cap_bit 2
# Last: the 2026-11-15 herdr config wipe. The control run destroys the fixture config.
attempt rm_herdr_config       sh -c "set -e; d=\$(ls -d \"\$XDG_CONFIG_HOME\"/herdr*); rm -rf \"\$d\"/config.toml"
echo "fence_env ${HERDR_FENCE:-unset}"
