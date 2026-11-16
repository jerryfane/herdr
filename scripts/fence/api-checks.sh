#!/bin/sh
# Pane-fence API checks (#420). Run by scripts/fence/container-test.sh once inside a
# fenced pane and once unfenced as the positive control, with OTHER set to another
# pane's id and SELF to the caller's own pane id. Prints "<name> ok|refused|error":
# refused = the pane fence turned the request down; error = the request reached its
# real handler and failed there (still proof it was not refused by the fence).
# Never run on a host.
set -u
[ -f /.dockerenv ] || { echo "refusing: not inside a throwaway container"; exit 2; }
: "${OTHER:?}" "${SELF:?}"

attempt() { # attempt <name> <cmd...>
  name=$1; shift
  out=$("$@" 2>&1); rc=$?
  if printf '%s' "$out" | grep -q 'fence_refused\|refused by pane fence'; then
    echo "$name refused"
  elif [ $rc -eq 0 ] && ! printf '%s' "$out" | grep -q '"error"'; then
    echo "$name ok"
  else
    echo "$name error"
  fi
}

attempt api_read_panes           herdr pane list
attempt api_rename_own_pane      herdr pane rename "$SELF" fence-self
attempt api_rename_other_pane    herdr pane rename "$OTHER" fence-other
attempt api_run_in_other_pane    herdr pane run "$OTHER" "true"
attempt api_send_keys_other_pane herdr pane send-keys "$OTHER" Enter
attempt api_reload_config        herdr server reload-config
attempt api_plugin_link          herdr plugin link /tmp
# The client socket is masked in fenced panes, so connect() fails: report it as refused.
if perl -MIO::Socket::UNIX -e 'IO::Socket::UNIX->new(Type=>SOCK_STREAM(),Peer=>"$ENV{XDG_CONFIG_HOME}/herdr/herdr-client.sock") or exit 1' 2>/dev/null; then
  echo "api_client_socket ok"
else
  echo "api_client_socket refused"
fi
