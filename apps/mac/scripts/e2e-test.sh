#!/bin/bash
# End-to-end test in a throwaway folder: two "Macs" on this machine, each with its own
# Shrug app, ~/Shrug mount and home folder, sharing a plain folder as the bucket. It uses
# only shrug and ordinary file commands. Touches nothing outside the test folder.
#
#   apps/mac/scripts/e2e-test.sh            # KEEP=1 keeps the folder afterwards
#
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
BIN="$HERE/.build/debug"
# The real path (/private/var/..., no "//"), because that's what `mount` prints.
T=$(cd "$(mktemp -d "${TMPDIR:-/tmp}/shrug-e2e.XXXXXX")" && pwd -P)
PW="e2e correct horse battery"
FAILS=0
D1=""
D2=""

pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAILS=$((FAILS + 1)); }
check() { local what=$1; shift; if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi; }
wait_for() { local what=$1 secs=$2; shift 2; for _ in $(seq 1 "$secs"); do "$@" >/dev/null 2>&1 && { pass "$what"; return; }; sleep 1; done; fail "$what"; }
refused() { ! "$@"; }
mounted() { mount | grep -q " on $1 ("; }

# Each Mac's environment. `env` (not a shell function) so that $! is the app itself.
MAC1=(SHRUG_STATE_DIR="$T/state1" SHRUG_MOUNT_DIR="$T/mnt1" SHRUG_HOME_DIR="$T/home1" SHRUG_SOCKET="$T/s1")
MAC2=(SHRUG_STATE_DIR="$T/state2" SHRUG_MOUNT_DIR="$T/mnt2" SHRUG_HOME_DIR="$T/home2" SHRUG_SOCKET="$T/s2")
mac1() { env "${MAC1[@]}" "$@"; }
mac2() { env "${MAC2[@]}" "$@"; }
ctl1() { mac1 "$BIN/shrug" "$@"; }
ctl2() { mac2 "$BIN/shrug" "$@"; }
status1_has() { ctl1 status | grep -q "$1"; }
status2_has() { ctl2 status | grep -q "$1"; }
answers() { local input=$1; shift; printf '%b' "$input" | "$@"; }
no_names_on_disk() { ! grep -rqa -e id_e2e -e drop.txt -e "PRIVATE KEY" "$1"; }

cleanup() {
  [ -n "$D1" ] && kill "$D1" 2>/dev/null
  [ -n "$D2" ] && kill "$D2" 2>/dev/null
  wait 2>/dev/null
  for m in "$T/mnt1" "$T/mnt2"; do
    if mounted "$m"; then /usr/sbin/diskutil unmount force "$m" >/dev/null 2>&1; fi
    chmod 700 "$m" 2>/dev/null
  done
  if [ "${KEEP:-0}" = 1 ]; then echo "Kept $T"; else rm -rf "$T"; fi
}
trap cleanup EXIT

echo "Building…"
(cd "$HERE" && swift build -q) || exit 1

mkdir -p "$T/home1/.ssh" "$T/home2/.ssh" "$T/bucket"
export SHRUG_NO_TOUCHID=1 SHRUG_TEST_KDF_ITERATIONS=1000 SHRUG_SYNC_SECONDS=1 SHRUG_DEBOUNCE_SECONDS=1

echo "1. First Mac"
env "${MAC1[@]}" "$BIN/ShrugApp" --headless >"$T/daemon1.log" 2>&1 &
D1=$!
wait_for "app answers" 10 ctl1 status
wait_for "~/Shrug mounted" 10 mounted "$T/mnt1"
check "setup creates the vault" answers "$PW\n" ctl1 setup --storage folder --path "$T/bucket" --device mac1 --profile work
check "status says unlocked" status1_has "Shrug:     unlocked"
check "~/Shrug shows the three folders" sh -c "[ \"\$(ls '$T/mnt1' | tr '\n' ' ')\" = 'local remote synced ' ]"
check "nothing can go next to them" refused touch "$T/mnt1/stray.txt"

echo "2. Files and links"
printf 'PRIVATE KEY e2e\n' >"$T/home1/.ssh/id_e2e"
check "add moves a file in and links it" ctl1 add "$T/home1/.ssh/id_e2e"
check "the link points into ~/Shrug" sh -c "[ \"\$(readlink '$T/home1/.ssh/id_e2e')\" = '$T/mnt1/synced/ssh/id_e2e' ]"

MOUNT_READS=1
if ! cat "$T/home1/.ssh/id_e2e" >/dev/null 2>"$T/read.err"; then
  MOUNT_READS=0
  echo "  NOTE reading through the mount failed: $(cat "$T/read.err")"
  # macOS asks once per app; after a "Don't Allow" it refuses without asking.
  APP=${__CFBundleIdentifier:-your terminal app}
  echo "       If it says 'Operation not permitted', macOS refused $APP access to network volumes."
  echo "       Turn on Network Volumes for it in System Settings > Privacy & Security > Files & Folders,"
  echo "       or run 'tccutil reset SystemPolicyNetworkVolumes $APP' so macOS asks again. Then re-run."
  echo
  echo "Stopping: everything after this reads through the mount."
  exit 1
fi
check "read through the link" grep -q 'PRIVATE KEY e2e' "$T/home1/.ssh/id_e2e"
check "ssh-style permission check sees 600" sh -c "[ \"\$(stat -L -f %Lp '$T/home1/.ssh/id_e2e')\" = 600 ]"
check "a link to a missing file creates it empty" ctl1 add "$T/home1/project/.env" synced/project/env
check "...and it's empty" sh -c "[ -L '$T/home1/project/.env' ] && [ ! -s '$T/home1/project/.env' ]"
check "drop a file into synced/" cp "$T/home1/.ssh/id_e2e" "$T/mnt1/synced/drop.txt"
check "drop a file into local/" sh -c "echo 'this Mac only' > '$T/mnt1/local/mine.txt'"
head -c 3000000 /dev/urandom >"$T/big.bin"
check "copy 3 MB into remote/" cp "$T/big.bin" "$T/mnt1/remote/big.bin"
wait_for "everything uploads" 20 status1_has "up to date"
check "the remote file still reads, streamed" cmp "$T/big.bin" "$T/mnt1/remote/big.bin"
check "no names or contents in ~/.shrug" no_names_on_disk "$T/state1"
check "...or in the bucket" no_names_on_disk "$T/bucket"

echo "3. Lock"
check "lock" ctl1 lock
check "status says locked" status1_has "Shrug:     locked"
check "status names nothing" refused status1_has "id_e2e"
check "the folders look empty" sh -c "[ -z \"\$(ls -A '$T/mnt1/synced' '$T/mnt1/remote' '$T/mnt1/local' | grep -v ':' | tr -d '\n')\" ]"
check "reading through the link is refused" refused cat "$T/home1/.ssh/id_e2e"
check "unlock with the password" answers "$PW\n" ctl1 unlock --password
check "readable again" grep -q 'PRIVATE KEY e2e' "$T/home1/.ssh/id_e2e"

echo "4. A second Mac"
env "${MAC2[@]}" "$BIN/ShrugApp" --headless >"$T/daemon2.log" 2>&1 &
D2=$!
wait_for "second app answers" 10 ctl2 status
wait_for "second ~/Shrug mounted" 10 mounted "$T/mnt2"
printf 'old key on mac2\n' >"$T/home2/.ssh/id_e2e"
check "a wrong password is refused" refused answers "not the password at all\n" ctl2 setup --storage folder --path "$T/bucket" --device mac2 --profile work
check "...and nothing is set up" test ! -e "$T/state2/keyring.json"
# Its own ~/.ssh/id_e2e collides: answer "s" (keep Shrug's version).
check "setup with the password, keeping Shrug's key" answers "$PW\ns\n" ctl2 setup --storage folder --path "$T/bucket" --device mac2 --profile work
check "its key is now the link" sh -c "[ -L '$T/home2/.ssh/id_e2e' ] && grep -q 'PRIVATE KEY e2e' '$T/home2/.ssh/id_e2e'"
check "its own file was deleted" test ! -e "$T/home2/.ssh/id_e2e.before-shrug"
check "synced/ files arrived" grep -q 'PRIVATE KEY e2e' "$T/mnt2/synced/drop.txt"
check "local/ files didn't" test ! -e "$T/mnt2/local/mine.txt"
check "remote/ files are listed and read" cmp "$T/big.bin" "$T/mnt2/remote/big.bin"
check "an edit through a link on mac2..." sh -c "echo 'edited on mac2' >> '$T/home2/.ssh/id_e2e'"
wait_for "...reaches mac1" 20 grep -q 'edited on mac2' "$T/home1/.ssh/id_e2e"
check "mac1 lists both Macs" status1_has "all Macs: mac1, mac2"

echo "5. Offline"
mv "$T/bucket" "$T/bucket.away"
check "save while offline" sh -c "echo 'written offline' > '$T/mnt1/synced/plane.txt'"
wait_for "status says offline, waiting" 15 status1_has "offline, 1 change waiting"
mv "$T/bucket.away" "$T/bucket"
wait_for "back online, it uploads" 20 status1_has "up to date"
wait_for "and reaches mac2" 20 grep -q 'written offline' "$T/mnt2/synced/plane.txt"

echo "6. Remove a link"
check "remove" ctl1 remove "$T/home1/project/.env"
check "the link is gone" test ! -e "$T/home1/project/.env"
check "the file stays in ~/Shrug" test -e "$T/mnt1/synced/project/env"
wait_for "...and on mac2 too" 20 test ! -e "$T/home2/project/.env"

echo "7. Quit"
kill "$D1" "$D2"
wait "$D1" "$D2" 2>/dev/null
D1=""; D2=""
both_unmounted() { ! mounted "$T/mnt1" && ! mounted "$T/mnt2"; }
wait_for "both folders unmounted" 10 both_unmounted
check "~/Shrug is empty and can't be written to" sh -c "[ -z \"\$(ls -A '$T/mnt1')\" ] && ! touch '$T/mnt1/x' 2>/dev/null"

echo
if [ $FAILS = 0 ]; then echo "All checks passed."; else echo "$FAILS check(s) failed. Logs: $T/daemon1.log $T/daemon2.log"; KEEP=1; fi
exit $FAILS
