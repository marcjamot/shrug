# Shrug

Shrug keeps your private files (SSH keys, kubeconfigs, API tokens, customer data) encrypted, on your Mac and in a cloud bucket you own. While you work they are normal files. When the Mac locks, Shrug locks with it and nothing can be read.

It protects your files if the Mac is lost or stolen. It is not built to stop a skilled attacker who is already on it.

> [!NOTE]
> The code in this repository is written by an AI agent and reviewed by a computer engineer.

> [!NOTE]
> The current version only supports macOS.

## What it offers

Shrug gives you two places for private files. Both lock when the screen locks, the Mac sleeps or you switch user, and a fingerprint or your Shrug password unlocks them.

| | `~/Shrug` | `~/ShrugDisk` |
|---|---|---|
| For | Secrets your tools read: keys, tokens, configs | Data you work on: code, customer files, large files |
| Kept | Your choice per folder: every Mac, the bucket only, or this Mac only | On this Mac only |
| Reached | At the usual path: `~/.ssh/id_ed25519` is a link into `~/Shrug` | Inside `~/ShrugDisk` |
| Speed | Fine for single files, slow for thousands | As fast as the Mac's own disk |
| While locked | Opening a file asks for your fingerprint | Empty until Shrug unlocks. Shrug asks once when you return to the Mac |

`~/Shrug` has three folders, which decide where a file is kept:

- `synced/` is on every Mac, even offline.
- `remote/` stays in the bucket and is fetched when you open it.
- `local/` never leaves this Mac.

`local/` and `~/ShrugDisk` both stay on this Mac, and Shrug backs up neither. They differ the way the two columns do. `local/` is for a secret that a tool opens through a link, and it asks for your fingerprint when opened. `~/ShrugDisk` is for everything you work on: it is fast, has no links, and is empty while Shrug is locked.

Files are encrypted before upload, names included, so the storage provider can't read them.

## How to use it

1. Create a Google Cloud Storage bucket and a service account with the Storage Object User role on it.
2. Run `./setup` on each Mac. To update, pull the latest version and run it again.
3. Add files. `shrug add ~/.ssh/id_ed25519` moves the key to `~/Shrug/synced/ssh/id_ed25519` and leaves a link at the old path. You can also put files straight into `~/Shrug` or `~/ShrugDisk`.

`shrug status` shows what Shrug is doing, and `shrug help` lists every command.

## License

MIT. See [LICENSE](LICENSE).
