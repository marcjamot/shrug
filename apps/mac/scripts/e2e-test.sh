#!/bin/bash
# End-to-end test in a throwaway folder: two "Macs" on this machine, each with its own
# Shrug app, ~/Shrug mount and home folder, sharing a plain folder as the bucket. It uses
# only shrug and ordinary file commands. Touches nothing outside the test folder.
#
#   apps/mac/scripts/e2e-test.sh            # KEEP=1 keeps the folder afterwards
#
# LOCK_SCREEN=1 also really locks your screen, to check that Shrug locks with it. That needs
# "Require password after screen saver begins or display is turned off" set to Immediately
# (System Settings > Lock Screen). Unlock your Mac afterwards; the script carries on meanwhile.
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
# within 60 tar ...: the command works, and takes no longer than that many seconds.
within() { local secs=$1 start=$SECONDS; shift; "$@" && [ $((SECONDS - start)) -le "$secs" ]; }

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
ls "$T/mnt1/synced" >/dev/null
check "a link to a missing file creates it empty" ctl1 add "$T/home1/project/.env" synced/project/env
check "...and it's empty" sh -c "[ -L '$T/home1/project/.env' ] && [ ! -s '$T/home1/project/.env' ]"
wait_for "a folder listed before shows what Shrug added" 3 sh -c "ls '$T/mnt1/synced' | grep -q project"
check "drop a file into synced/" cp "$T/home1/.ssh/id_e2e" "$T/mnt1/synced/drop.txt"
check "drop a file into local/" sh -c "echo 'this Mac only' > '$T/mnt1/local/mine.txt'"
head -c 3000000 /dev/urandom >"$T/big.bin"
check "copy 3 MB into remote/" cp "$T/big.bin" "$T/mnt1/remote/big.bin"
wait_for "everything uploads" 20 status1_has "up to date"
check "the remote file still reads, streamed" cmp "$T/big.bin" "$T/mnt1/remote/big.bin"
check "no names or contents in ~/.shrug" no_names_on_disk "$T/state1"
check "...or in the bucket" no_names_on_disk "$T/bucket"

echo "3. Lock"
# What the system could still be holding: a file's contents, an open file, the folders' names.
cat "$T/mnt1/local/mine.txt" "$T/mnt1/synced/drop.txt" >/dev/null
ls -la "$T/mnt1/synced" "$T/mnt1/remote" "$T/mnt1/local" >/dev/null
exec 3<"$T/mnt1/local/mine.txt"
check "lock" ctl1 lock
check "a file that was open can't be read any more" refused sh -c 'cat <&3'
check "nor one that was read just before" refused cat "$T/mnt1/local/mine.txt"
exec 3<&-
check "status says locked" status1_has "Shrug:     locked"
check "status names nothing" refused status1_has "id_e2e"
wait_for "the folders look empty" 3 sh -c "[ -z \"\$(ls -A '$T/mnt1/synced' '$T/mnt1/remote' '$T/mnt1/local' | grep -v ':' | tr -d '\n')\" ]"
check "reading through the link is refused" refused cat "$T/home1/.ssh/id_e2e"
check "unlock with the password" answers "$PW\n" ctl1 unlock --password
check "readable again" grep -q 'PRIVATE KEY e2e' "$T/home1/.ssh/id_e2e"
wait_for "the folders list their files again" 3 sh -c "ls '$T/mnt1/synced' | grep -q drop.txt && ls '$T/mnt1/local' | grep -q mine.txt"

echo "4. A second Mac"
env "${MAC2[@]}" "$BIN/ShrugApp" --headless >"$T/daemon2.log" 2>&1 &
D2=$!
wait_for "second app answers" 10 ctl2 status
wait_for "second ~/Shrug mounted" 10 mounted "$T/mnt2"
printf 'old key on mac2\n' >"$T/home2/.ssh/id_e2e"
check "a wrong password is refused" refused answers "not the password at all\n" ctl2 setup --storage folder --path "$T/bucket" --device mac2 --profile work
check "...and nothing is set up" test ! -e "$T/state2/keyring.json"
# It's asked to place mac1's links here ("y"); its own ~/.ssh/id_e2e collides: "s" (keep Shrug's).
check "setup with the password, keeping Shrug's key" answers "$PW\ny\ns\n" ctl2 setup --storage folder --path "$T/bucket" --device mac2 --profile work
check "its key is now the link" sh -c "[ -L '$T/home2/.ssh/id_e2e' ] && grep -q 'PRIVATE KEY e2e' '$T/home2/.ssh/id_e2e'"
check "its own file was deleted" test ! -e "$T/home2/.ssh/id_e2e.before-shrug"
check "synced/ files arrived" grep -q 'PRIVATE KEY e2e' "$T/mnt2/synced/drop.txt"
check "local/ files didn't" test ! -e "$T/mnt2/local/mine.txt"
check "remote/ files are listed and read" cmp "$T/big.bin" "$T/mnt2/remote/big.bin"
check "an edit through a link on mac2..." sh -c "echo 'edited on mac2' >> '$T/home2/.ssh/id_e2e'"
wait_for "...reaches mac1" 20 grep -q 'edited on mac2' "$T/home1/.ssh/id_e2e"
check "mac1 lists both Macs" status1_has "all Macs: mac1, mac2"

echo "5. Offline"
ls "$T/mnt2/synced" >/dev/null
mv "$T/bucket" "$T/bucket.away"
check "save while offline" sh -c "echo 'written offline' > '$T/mnt1/synced/plane.txt'"
wait_for "status says offline, waiting" 15 status1_has "offline, 1 change waiting"
mv "$T/bucket.away" "$T/bucket"
wait_for "back online, it uploads" 20 status1_has "up to date"
wait_for "and reaches mac2" 20 grep -q 'written offline' "$T/mnt2/synced/plane.txt"
wait_for "...where a folder listed before shows it" 3 sh -c "ls '$T/mnt2/synced' | grep -q plane.txt"

echo "6. Remove a link"
check "remove" ctl1 remove "$T/home1/project/.env"
check "the link is gone" test ! -e "$T/home1/project/.env"
check "the file stays in ~/Shrug" test -e "$T/mnt1/synced/project/env"
wait_for "...and on mac2 too" 20 test ! -e "$T/home2/project/.env"
check "rename a linked file in ~/Shrug" mv "$T/mnt1/synced/ssh/id_e2e" "$T/mnt1/synced/ssh/id_work"
wait_for "the link follows" 10 sh -c "[ \"\$(readlink '$T/home1/.ssh/id_e2e')\" = '$T/mnt1/synced/ssh/id_work' ]"
check "...and still reads" grep -q 'PRIVATE KEY e2e' "$T/home1/.ssh/id_e2e"
wait_for "...on mac2 too" 20 sh -c "[ \"\$(readlink '$T/home2/.ssh/id_e2e')\" = '$T/mnt2/synced/ssh/id_work' ]"

echo "7. Many files, large files"
mkdir -p "$T/tree"
for i in $(seq 1 500); do mkdir -p "$T/tree/dir$((i % 20))"; echo "file $i" >"$T/tree/dir$((i % 20))/file$i.txt"; done
tar -C "$T" -cf "$T/tree.tar" tree
# Rewriting the whole index for every file took minutes here.
check "500 files extract into local/ in seconds" within 60 tar -C "$T/mnt1/local" -xf "$T/tree.tar"
check "...all of them" sh -c "[ \"\$(find '$T/mnt1/local/tree' -type f | wc -l | tr -d ' ')\" = 500 ]"
check "500 files extract into synced/ in seconds" within 60 tar -C "$T/mnt1/synced" -xf "$T/tree.tar"
wait_for "they upload" 120 status1_has "up to date"
wait_for "...and reach mac2, every one the same" 120 diff -r "$T/tree" "$T/mnt2/synced/tree"
check "the 500 delete in seconds too" within 60 rm -rf "$T/mnt1/local/tree"
check "an extended attribute sticks to its file" sh -c "xattr -w user.note hello '$T/mnt1/local/mine.txt' && [ \"\$(xattr -p user.note '$T/mnt1/local/mine.txt')\" = hello ]"
check "...in a ._ file that listings leave out" sh -c "[ -e '$T/mnt1/local/._mine.txt' ] && ! ls -A '$T/mnt1/local' | grep -q '^\._'"
# With folder attributes cached, the system once took "no ._ file yet" for good and lost these.
check "a file made after its folder was listed takes one too" sh -c "echo later > '$T/mnt1/local/later.txt' && xattr -w user.note later '$T/mnt1/local/later.txt' && sleep 2 && [ \"\$(xattr -p user.note '$T/mnt1/local/later.txt')\" = later ]"
check "a program's fsync works" python3 -I -c "
import os
fd = os.open('$T/mnt1/synced/fsynced.txt', os.O_WRONLY | os.O_CREAT, 0o600)
os.write(fd, b'on the disk')
os.fsync(fd)
os.close(fd)"
# Just past what used to be the largest file Shrug took (1 GiB).
head -c 1200000000 /dev/urandom >"$T/huge.bin"
check "a 1.2 GB file goes into synced/" cp "$T/huge.bin" "$T/mnt1/synced/huge.bin"
check "...and reads back the same" cmp "$T/huge.bin" "$T/mnt1/synced/huge.bin"
wait_for "it uploads" 180 status1_has "up to date"
wait_for "...and reaches mac2" 180 test -e "$T/mnt2/synced/huge.bin"
check "...intact" cmp "$T/huge.bin" "$T/mnt2/synced/huge.bin"
check "lock and unlock" sh -c "env ${MAC1[*]} '$BIN/shrug' lock && printf '%s\n' '$PW' | env ${MAC1[*]} '$BIN/shrug' unlock --password"
check "the extended attribute lasted until the lock" sh -c "grep -q 'this Mac only' '$T/mnt1/local/mine.txt' && ! xattr -p user.note '$T/mnt1/local/mine.txt'"

echo "8. A crash"
check "a new file, a new folder and a rename" sh -c "echo 'made just before' > '$T/mnt1/local/last.txt' && mkdir '$T/mnt1/synced/lastdir' && mv '$T/mnt1/local/mine.txt' '$T/mnt1/local/moved.txt'"
kill -9 "$D1"
wait "$D1" 2>/dev/null
env "${MAC1[@]}" "$BIN/ShrugApp" --headless >>"$T/daemon1.log" 2>&1 &
D1=$!
wait_for "the app starts again" 60 ctl1 status
wait_for "...and unlocks" 60 answers "$PW\n" ctl1 unlock --password
wait_for "the new file is there" 60 grep -q 'made just before' "$T/mnt1/local/last.txt"
check "...and the folder, and the rename" sh -c "[ -d '$T/mnt1/synced/lastdir' ] && grep -q 'this Mac only' '$T/mnt1/local/moved.txt' && [ ! -e '$T/mnt1/local/mine.txt' ]"
check "...and the large file" cmp "$T/huge.bin" "$T/mnt1/synced/huge.bin"
wait_for "it syncs again" 60 status1_has "up to date"

if [ "${LOCK_SCREEN:-0}" = 1 ]; then
  echo "9. Screen lock (unlock your Mac when it's done)"
  both_unlocked() { status1_has "Shrug:     unlocked" && status2_has "Shrug:     unlocked"; }
  check "both are unlocked" both_unlocked
  pmset displaysleepnow
  wait_for "mac1 locks with the screen" 5 status1_has "Shrug:     locked"
  wait_for "mac2 locks with the screen" 5 status2_has "Shrug:     locked"
else
  echo "9. Screen lock: skipped (LOCK_SCREEN=1 runs it, and locks your screen)"
fi

echo "10. Quit"
kill "$D1" "$D2"
wait "$D1" "$D2" 2>/dev/null
D1=""; D2=""
both_unmounted() { ! mounted "$T/mnt1" && ! mounted "$T/mnt2"; }
wait_for "both folders unmounted" 10 both_unmounted
check "~/Shrug is empty and can't be written to" sh -c "[ -z \"\$(ls -A '$T/mnt1')\" ] && ! touch '$T/mnt1/x' 2>/dev/null"

echo
if [ $FAILS = 0 ]; then echo "All checks passed."; else echo "$FAILS check(s) failed. Logs: $T/daemon1.log $T/daemon2.log"; KEEP=1; fi
exit $FAILS
