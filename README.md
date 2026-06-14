# airgap

Hide secrets from AI agents, while letting them do their work. `airgap`
launches a target program (e.g. an AI coding agent) inside its own mount
namespace and transparently replaces secrets (e.g. `.env`, SSH/PGP private
keys) with redacted versions.

An agent running under `airgap` can still **read** and **modify** the protected
files, but it never sees the actual secrets.

## Protected secrets

So far `airgap` protects:

- **`.env` and `.env.*`** (e.g. `.env.local`, `.env.production`) — matched by
  filename. Values are redacted to `<redacted value>` while keys stay visible;
  edits, additions, and deletions are persisted back to the real file.
- **SSH / PGP private keys** — matched by content (any file starting with a
  private-key header: OpenSSH/ed25519, RSA, EC/PKCS#8, or PGP). The key body is
  redacted while the `BEGIN`/`END` markers are kept.

More secret types will be added.

These are redacted anywhere under the **working directory** or your **home
directory** (`$HOME`) — so both a project's `.env` and `~/.ssh` keys are covered.
Matching is dynamic: files created after launch are caught too.

## Install

```
cargo install airgap
```

`airgap` creates a mount namespace and mounts a FUSE filesystem, which require
`CAP_SYS_ADMIN`. Grant it to the installed binary once so you can run it as a
normal user (no `sudo` per invocation):

```
sudo setcap cap_sys_admin+ep "$(command -v airgap)"
```

Note: the capability is an attribute of the file, so it is lost whenever the
binary is reinstalled. Re-run `setcap` after each `cargo install`.

## Usage

```
airgap <program> [args...]
```

`airgap` runs `<program>` with `[args...]`, passing through argv, the
environment, and the working directory unchanged. When `<program>` exits,
`airgap` exits with the same code.

### Demo

Compare `.env`'s content with and without using `airgap`:

```
$ cat .env
API_KEY=sk-live-9f8c2a1b4e7d
DB_PASSWORD=hunter2

$ airgap cat .env
API_KEY=<redacted value>
DB_PASSWORD=<redacted value>
```

With an AI agent:

```
$ airgap claude

 show me ./test/fixtures/.env contents

  Read 1 file

Here's the file:

DATABASE_URL="<redacted value>"
API_KEY="<redacted value>"
AWS_SECRET_ACCESS_KEY="<redacted value>"
DEBUG="<redacted value>"

...
```

## Use with Claude / opencode

To always run your AI agent under `airgap`, alias it in your shell config
(`~/.bashrc`, `~/.zshrc`, ...):

```
alias claude="airgap claude"
alias opencode="airgap opencode"
```

Now `claude` (or `opencode`) transparently runs inside `airgap`.
