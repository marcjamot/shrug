#!/bin/bash
# Builds Shrug.app, installs it into ~/Applications and links shrug into ~/.local/bin.
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)

# bash, in case a zip download lost the executable bits.
bash "$HERE/scripts/build-app.sh"
mkdir -p "$HOME/Applications" "$HOME/.local/bin"
if pgrep -xq Shrug; then
  osascript -e 'quit app "Shrug"' || true
  sleep 2
fi
rm -rf "$HOME/Applications/Shrug.app"
cp -R "$HERE/build/Shrug.app" "$HOME/Applications/"
ln -sf "$HOME/Applications/Shrug.app/Contents/Helpers/shrug" "$HOME/.local/bin/shrug"
echo "Installed ~/Applications/Shrug.app and ~/.local/bin/shrug"
case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) echo "Add ~/.local/bin to your PATH to use shrug." ;; esac
