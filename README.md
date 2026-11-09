# Shrug

Shrug keeps your SSH keys, kubeconfigs, API tokens and other private files encrypted in a cloud bucket you own. While you use your computer, they work like normal files. When the computer locks, Shrug locks too and the files can't be read.

> [!NOTE]
> The code in this repository is written by an AI agent and reviewed by a computer engineer.

> [!NOTE]
> The current version only supports macOS.

## How it works

Shrug stores its data in `~/.shrug`. You open and edit your files in `~/Shrug`, which has three folders:

- `synced/` is for files you need on every computer, even offline.
- `remote/` is for files that shouldn't be stored on any computer. They stay in the bucket and are only held in memory while you use them.
- `local/` is for files that should never leave this computer.

Shrug puts links at the paths your tools already use. Your SSH key can be in `~/Shrug/synced/ssh/id_ed25519`, and `~/.ssh/id_ed25519` is a link to it.

All files are encrypted on the computer and in the bucket. Shrug locks when the screen locks or the computer sleeps. `~/Shrug` then looks empty, and opening a file prompts for your fingerprint or password.

## Profiles

A profile lets each computer have its own set of links. Your work laptop can follow a `work` profile that links the work kubeconfig, while your home computer follows a `home` profile without it. Several computers can follow the same profile. A profile only decides the links, not which files are in `~/Shrug`.

## Security

Shrug keeps your files safe if you lose your computer. It won't stop a skilled attacker.

- Files are encrypted on your computer (AES-256-GCM) before they're uploaded, names included. The storage provider only sees random names, rough sizes and when files change.
- Your Shrug password unlocks the vault key, which is stored in the bucket. Each computer also keeps a copy sealed by its security chip, so your fingerprint can unlock it.

Shrug doesn't protect copies that apps make on their own, such as autosaves, previews and exports. When two computers edit the same file, the newest edit wins, so an older edit made offline is lost.

## Setup

Create a Google Cloud Storage bucket and a service account with the Storage Object User role on it. Then run `./setup` on each computer.

## Usage

| Command | What it does |
|---|---|
| `shrug add ~/.kube/config` | Moves the file to `~/Shrug/synced/kube/config` and leaves a link in its place (creates the file if missing) |
| `shrug add ~/.kube/config synced/work/kubeconfig` | Same, but you pick where it goes |
| `shrug remove ~/.kube/config` | Removes the link but keeps the file in Shrug |
| `shrug use`, `shrug use work` | Lists profiles, or follows one (a new name creates it) |
| `shrug lock`, `shrug unlock` | Locks or unlocks Shrug |
| `shrug status` | Shows the lock state, profile, storage and links |

By default, `shrug add` uses the file's path relative to your home folder, minus the leading dot so it isn't hidden. Add `--remote` or `--local` to put the file in that folder instead of `synced/`.

If an app replaces a link with a real file when saving, Shrug moves the new file into `~/Shrug` and puts the link back. If a file already exists where a link should go, Shrug asks which version to keep and deletes the other.

Deleting or moving a file at its usual path, like `rm ~/.kube/config`, removes only the link. The file stays at `~/Shrug/synced/kube/config`, and nothing in `~/.shrug` is deleted. Other Macs that follow the same profile lose the link too.

Deleting or moving the file in `~/Shrug` changes the real file. Deleting `~/Shrug/synced/kube/config` deletes it on every Mac and removes the link at `~/.kube/config`. Renaming it, or moving it elsewhere in `synced/`, keeps the link working.

## License

MIT. See [LICENSE](LICENSE).
