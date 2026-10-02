#!/bin/sh
# =========================================================
# service-account — EasyWAF
# Installed as /usr/lib/easywaf/service-account and run by
# the package after an install and after every upgrade (the
# Debian postinst, and the RPM's post-install script).
#
# The service runs as the account `easywaf`, not root. This
# makes sure the account exists and owns its files, and
# brings a running service onto the new binary:
#
#   1. the group and the user, each created only when it is
#      not already there — an upgrade finds them, a first
#      install does not, and an administrator may have made
#      either one beforehand
#   2. a running service is stopped
#   3. /opt/easywaf and /var/log/easywaf are handed to the
#      account
#   4. the service is started again, if it was running
#
# The service is stopped before the files change hands, not
# restarted after. An installation upgraded from a release
# where it ran as root is still running as root at this
# point, and a file it created after the hand-over — a
# snapshot, a cache, SQLite's own journal — would belong to
# root, where the account cannot open it.
#
# The account comes first of all, so that a host where it
# cannot be created is left with its service running as it
# was, rather than stopped with nothing to start it as.
#
# Safe to run by hand, as root, to repair ownership.
# =========================================================
set -e

ACCOUNT=easywaf
UNIT=easywaf.service
DATA=/opt/easywaf
LOGS=/var/log/easywaf

have()        { command -v "$1" >/dev/null 2>&1; }
group_there() { getent group  "$ACCOUNT" >/dev/null 2>&1; }
user_there()  { getent passwd "$ACCOUNT" >/dev/null 2>&1; }

fail() {
    echo "easywaf: $1" >&2
    exit 1
}

# ── 1. The account ───────────────────────────────────────

if ! group_there; then
    have groupadd || fail "cannot create the group '$ACCOUNT': groupadd is not installed"
    groupadd --system "$ACCOUNT" || fail "could not create the group '$ACCOUNT'"
    echo "easywaf: created the group '$ACCOUNT'"
fi

if ! user_there; then
    have useradd || fail "cannot create the account '$ACCOUNT': useradd is not installed"
    # No login. The path differs between distributions.
    shell=/usr/sbin/nologin
    [ -x "$shell" ] || shell=/sbin/nologin
    [ -x "$shell" ] || shell=/bin/false
    # A system account with no home of its own: /opt/easywaf is where it lives.
    useradd --system --gid "$ACCOUNT" --home-dir "$DATA" --no-create-home \
            --shell "$shell" --comment "EasyWAF" "$ACCOUNT" \
        || fail "could not create the account '$ACCOUNT'"
    echo "easywaf: created the account '$ACCOUNT'"
fi

# ── 2. Stop a running service ────────────────────────────

was_running=no
if have systemctl; then
    # The unit file ships with the package and may have changed.
    systemctl daemon-reload >/dev/null 2>&1 || true
    if systemctl is-active --quiet "$UNIT" 2>/dev/null; then
        was_running=yes
        systemctl stop "$UNIT" >/dev/null 2>&1 || true
    fi
fi

# ── 3. Hand over the files ───────────────────────────────

# Every time, not only when the account was just created: it is cheap, and it
# repairs a file somebody made as root by hand.
#
# -h: a symbolic link is itself re-owned, never what it points at. This runs as
# root in a directory the account can write to, and following a link from there
# would hand the account a file of root's.
for dir in "$DATA" "$LOGS"; do
    if [ -d "$dir" ]; then
        chown -hR "$ACCOUNT:$ACCOUNT" "$dir"
    fi
done

# ── 4. Start it again ────────────────────────────────────

# Only a service that was running: a first install does not start one before
# any site is configured, and one an administrator stopped stays stopped.
if [ "$was_running" = yes ]; then
    if ! systemctl start "$UNIT" >/dev/null 2>&1; then
        # Said, not failed on: the package is installed, and failing here would
        # leave the package manager half-way through for a reason it cannot fix.
        echo "easywaf: the service did not start again. See: journalctl -u $UNIT" >&2
    fi
fi

exit 0
