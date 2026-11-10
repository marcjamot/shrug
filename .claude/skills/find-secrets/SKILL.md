---
name: find-secrets
description: Check this Mac for secret files that should move into Shrug (SSH keys, kubeconfigs, API tokens, cloud credentials, .env files, tokens in notes or shell configs), compare with what Shrug already manages, and suggest shrug commands. Use when asked what on this computer should go into Shrug, to audit secrets on a new or existing Mac, or after setting up Shrug.
---

# What on this Mac should move into Shrug

Produce a short list of secret files that aren't in Shrug yet, each with a
recommendation. The user is a developer; keep the report brief.

## Ground rules

- **Never print, copy or summarize secret values.** Report paths, sizes,
  permissions and the *kind* of secret ("GitHub token", "SSH private key").
  You may read a key file's first line (`-----BEGIN ... PRIVATE KEY-----`) and
  variable names in `.env` or shell files (`cut -d= -f1`), never what follows.
  To search contents, use `grep -l` or `grep -c`, which print only file names
  or counts.
- **Don't move anything yourself.** End with the commands, and run them only
  if the user says so, one at a time.
- Skip what Shrug already manages: run `shrug status` (it lists this Mac's
  links; unlock first if it says locked), and ignore symlinks into `~/Shrug`.

## Where to look

- `~/.ssh`: private keys (`id_*` and anything with a PRIVATE KEY header). Not
  `*.pub`, `known_hosts` or `authorized_keys`.
- Tool credentials: `~/.kube/config`, `~/.talos/`, `~/.aws/credentials`,
  `~/.config/gcloud/`, `~/.azure/`, `~/.docker/config.json` (only if it holds
  `auths`), `~/.npmrc`, `~/.pypirc`, `~/.netrc`, `~/.git-credentials`,
  `~/.config/gh/hosts.yml`, `~/.terraform.d/credentials.tfrc.json`, and other
  files under `~/.config` or dot folders named like `*token*`, `*secret*`,
  `*credential*`, `*key*` or `*.pem`.
- `.env*` files under `~/projects`, `~/code`, `~/src`, `~/Developer` and
  `~/Documents`. Skip `node_modules`, `.git`, build output and
  `.env.example` / `.env.sample`.
- Notes and documents holding tokens: file names with token, secret, password
  or key, plus `grep -l` for common token shapes (`ghp_`, `github_pat_`, `sk-`,
  `xox[bp]-`, `AKIA`, `-----BEGIN`).
- Shell startup files (`~/.zshrc`, `~/.zprofile`, `~/.bashrc`, `~/.profile`)
  that export tokens. Report the variable names only.

## Recommendations

- **Move to Shrug:** small files programs read from a fixed path in the home folder
  (Shrug doesn't link anything outside it, or in `~/Library/LaunchAgents`). `shrug add <path>`
  moves the file into `~/Shrug/synced/` and links it; by default it keeps the path's
  shape (`~/.kube/config` -> `synced/kube/config`). Suggest a clearer place when it
  helps (`synced/work/kubeconfig`). The link joins this Mac's profile, so every Mac
  following the same profile gets it.
- **Tokens in shell files:** move the exports into their own file (for example
  `~/.config/secrets.zsh`), `source` it from the shell file, and put that file in
  Shrug.
- **Tokens in notes:** suggest the password manager, or a separate file in Shrug.
- **Private documents:** drop them into `~/Shrug` instead of linking:
  `~/Shrug/synced/` to have them on every Mac, `~/Shrug/remote/` for large or rarely
  used files (kept in the bucket, streamed when opened), `~/Shrug/local/` for this
  Mac only.
- **Leave alone, and say why:** passwords and logins (password manager), public
  keys, caches, sockets, whole tool folders that are rewritten constantly
  (`~/.gnupg`, `~/.docker`), Shrug's own files in `~/.shrug`, and anything a
  background job (launchd, cron) must read, because macOS may refuse it access to
  `~/Shrug`, and nothing in it is readable while Shrug is locked.

## Report

Three short groups: **Move**, **Consider**, **Leave**. One line each: path,
kind, and where it would go in `~/Shrug`. Then the commands, for example:

```
shrug add ~/.ssh/id_ed25519
shrug add ~/.kube/config synced/work/kubeconfig
```

Shrug uploads by itself while unlocked; there's nothing to push.
