#!/bin/bash
# Upgrade test in a throwaway folder: an older Shrug, built from git, sets up a vault with a
# few files and a link, then quits; this version opens the same Mac and vault, upgrades them,
# and must still show everything (and what's new since). Touches nothing outside the test folder.
#
#   apps/mac/scripts/upgrade-test.sh [old-revision]     # default: the last commit (HEAD)
#                                                       # KEEP=1 keeps the folder afterwards
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
OLD_REV=${1:-HEAD}
# The real path (/private/var/..., no "//"), because that's what `mount` prints.
T=$(cd "$(mktemp -d "${TMPDIR:-/tmp}/shrug-upgrade.XXXXXX")" && pwd -P)
PW="upgrade correct horse battery"
FAILS=0
APP=""

pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAILS=$((FAILS + 1)); }
check() { local what=$1; shift; if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi; }
wait_for() { local what=$1 secs=$2; shift 2; for _ in $(seq 1 "$secs"); do "$@" >/dev/null 2>&1 && { pass "$what"; return; }; sleep 1; done; fail "$what"; }
mounted() { mount | grep -q " on $T/mnt ("; }
unmounted() { ! mounted; }
disk_attached() { mount | grep -q " on $T/home/ShrugDisk ("; }

MAC=(SHRUG_STATE_DIR="$T/state" SHRUG_MOUNT_DIR="$T/mnt" SHRUG_HOME_DIR="$T/home" SHRUG_SOCKET="$T/s")
ctl() { env "${MAC[@]}" "$BIN/shrug" "$@"; }
status_has() { ctl status | grep -q "$1"; }
start() { env "${MAC[@]}" "$BIN/ShrugApp" --headless >>"$T/app.log" 2>&1 & APP=$!; }
quit() { kill "$APP"; wait "$APP" 2>/dev/null; APP=""; }
vault_format() { grep -Eo '"version" ?: ?[0-9]+' "$T/bucket/m/keyring" | grep -Eo '[0-9]+$'; }

cleanup() {
  [ -n "$APP" ] && kill "$APP" 2>/dev/null
  wait 2>/dev/null
  if mounted; then /usr/sbin/diskutil unmount force "$T/mnt" >/dev/null 2>&1; fi
  if disk_attached; then /usr/bin/hdiutil detach "$T/home/ShrugDisk" -force >/dev/null 2>&1; fi
  chmod 700 "$T/mnt" "$T/home/ShrugDisk" 2>/dev/null
  rm -f "${TMPDIR:-/tmp}"/*"$(basename "$T")"*.lock # SwiftPM's locks for the old version's build
  if [ "${KEEP:-0}" = 1 ]; then echo "Kept $T"; else rm -rf "$T"; fi
}
trap cleanup EXIT

echo "Building $OLD_REV and this version…"
mkdir -p "$T/old" "$T/home/.ssh" "$T/bucket"
ROOT=$(git -C "$HERE" rev-parse --show-toplevel)
git -C "$ROOT" archive "$OLD_REV:${HERE#"$ROOT"/}" | tar -x -C "$T/old" || exit 1
(cd "$T/old" && swift build -q) || exit 1
(cd "$HERE" && swift build -q) || exit 1
export SHRUG_NO_TOUCHID=1 SHRUG_TEST_KDF_ITERATIONS=1000 SHRUG_SYNC_SECONDS=1 SHRUG_DEBOUNCE_SECONDS=1

echo "1. The old Shrug"
BIN="$T/old/.build/debug"
start
wait_for "it mounts ~/Shrug" 10 mounted
check "it creates the vault" sh -c "printf '%s\n' '$PW' | env ${MAC[*]} '$BIN/shrug' setup --storage folder --path '$T/bucket' --device mac --profile work"
printf 'OLD PRIVATE KEY\n' >"$T/home/.ssh/id_upgrade"
check "it links a key" ctl add "$T/home/.ssh/id_upgrade"
head -c 200000 /dev/urandom >"$T/big.bin"
check "it keeps a synced/ file" cp "$T/big.bin" "$T/mnt/synced/big.bin"
check "a remote/ file" cp "$T/big.bin" "$T/mnt/remote/big.bin"
check "and a local/ file" sh -c "echo 'this Mac only' > '$T/mnt/local/mine.txt'"
wait_for "everything uploads" 20 status_has "up to date"
mv "$T/bucket" "$T/bucket.away"
check "a change made offline waits" sh -c "echo 'written offline' > '$T/mnt/synced/offline.txt'"
wait_for "...and is waiting when it quits" 10 status_has "1 change waiting"
quit
mv "$T/bucket.away" "$T/bucket"
wait_for "it quits" 10 unmounted
OLD_FORMAT=$(vault_format)

echo "2. This Shrug"
BIN="$HERE/.build/debug"
start
wait_for "it mounts ~/Shrug" 10 mounted
check "it unlocks with the password" sh -c "printf '%s\n' '$PW' | env ${MAC[*]} '$BIN/shrug' unlock --password"
wait_for "it syncs" 20 status_has "up to date"
NEW_FORMAT=$(cat "$T/state/version" 2>/dev/null)
check "this Mac's files are in this version's format ($OLD_FORMAT -> ${NEW_FORMAT:-none})" test -n "$NEW_FORMAT" -a "$NEW_FORMAT" -ge "$OLD_FORMAT"
check "the vault is upgraded too" test "$(vault_format)" = "$NEW_FORMAT"
check "the key reads through its link" grep -q 'OLD PRIVATE KEY' "$T/home/.ssh/id_upgrade"
check "the link is still ok" sh -c "env ${MAC[*]} '$BIN/shrug' status | grep -q 'ok  ~/.ssh/id_upgrade'"
check "the synced/ file is intact" cmp "$T/big.bin" "$T/mnt/synced/big.bin"
check "the remote/ file streams" cmp "$T/big.bin" "$T/mnt/remote/big.bin"
check "the local/ file is there" grep -q 'this Mac only' "$T/mnt/local/mine.txt"
check "the offline change went up" sh -c "grep -q 'written offline' '$T/mnt/synced/offline.txt' && env ${MAC[*]} '$BIN/shrug' status | grep -q 'up to date'"
check "and an edit still syncs" sh -c "echo more >> '$T/mnt/synced/offline.txt'"
wait_for "...up to the bucket" 20 status_has "up to date"
# Older versions had no ~/ShrugDisk: the first unlock makes one. (Skipped when the old version had it.)
if [ ! -e "$T/old/Sources/ShrugDaemon/Disk.swift" ]; then
  wait_for "it gets a ~/ShrugDisk" 15 disk_attached
  check "...that takes files" sh -c "echo 'on the new disk' > '$T/home/ShrugDisk/new.txt' && grep -q 'on the new disk' '$T/home/ShrugDisk/new.txt'"
fi
quit
wait_for "quitting ejects the disk" 10 sh -c "! mount | grep -q ' on $T/home/ShrugDisk ('"

echo
if [ $FAILS = 0 ]; then echo "All checks passed."; else echo "$FAILS check(s) failed. Log: $T/app.log"; KEEP=1; fi
exit $FAILS
