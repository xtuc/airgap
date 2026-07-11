# airgap

Security for the modern AI age.

> No security layer is perfect. airgap is still experimental. Contributions
> welcome!

## Protected secrets

`airgap` launches a target program (e.g. an AI coding agent) inside its own mount
namespace and transparently replaces secrets with redacted versions. A program
running under `airgap` can still **read** and **modify** protected files, but it
never sees the actual secrets. So far `airgap` protects:

- **`.env` and `.env.*`** (e.g. `.env.local`, `.env.production`) — matched by
  filename. Values are redacted to `<redacted value>` while keys stay visible;
  edits, additions, and deletions are persisted back to the real file.
- **SSH / PGP private keys** — matched by content (any file starting with a
  private-key header: OpenSSH/ed25519, RSA, EC/PKCS#8, or PGP). The key body is
  redacted while the `BEGIN`/`END` markers are kept.
- **`.npmrc`** — matched by filename. Auth-token and password values
  (`_authToken`, `_auth`, `_password`, including the per-registry
  `//registry/:_authToken` form) are redacted to `<redacted value>`, while
  registries, scopes, `email`, and comments stay visible; edits are persisted
  back to the real file.

More secret types will be added.

These are redacted anywhere under the **working directory** or your **home
directory** (`$HOME`) — so both a project's `.env` and `~/.ssh` keys are covered.
Matching is dynamic: files created after launch are caught too.

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

## File access permissions

An additional layer defends against malicious packages: `airgap` asks for your
permission when unexpected files are being accessed — for instance by a malicious
npm install script.

When the gate is active, airgap asks you to allow or reject the first read of
each new file. Approving a file grants only that file; decisions last for the
run. Each package manager comes with a list of pre-approved files.

For example, installing a malicious package whose `postinstall` script tries to
read your SSH keys and `.env`:

```
$ airgap npm install
...
airgap: npm wants to read the file /home/you/.ssh/id_rsa — allow? [y/N] n
airgap: npm wants to read the file /home/you/.env — allow? [y/N] n
```

Answer `n` to reject the access.

## Network interception

With the `--mitm` flag, `airgap` can transparently intercept the wrapped
program's HTTPS traffic, decrypt it, rewrite request headers per a YAML rule
set, and re-encrypt it to the real server. The client validates TLS normally — it
just trusts an ephemeral CA that `airgap` installs into the sandbox for the
duration of the run.

The wrapped program is placed in a private network namespace, and a user-space
TCP/IP stack + TLS proxy does the interception.

### Configure the rules

Rules live in a YAML file you name with `--mitm-config <path>`. There is no
default location and no search path — `--mitm` requires the flag, so the file in
effect is always the one on the command line. The examples below use the
in-repo `./mitm.yaml`:

```yaml
rules:
  - host: httpbin.org                    # matched exactly against the request's Host
    headers:                             # (case-insensitive, no subdomains); first match wins
      X-Airgap-Test: rewritten-by-airgap # override if present, add if absent
      X-Injected-By: airgap
```

A request whose `Host` header matches a rule gets that rule's headers applied.
Because header values can themselves be secrets, `mitm.yaml` is also
redacted when read from inside the sandbox (values become `<redacted value>`).

### Run it

```
$ airgap --mitm --mitm-config ./mitm.yaml --allow-unknown-program \
    curl -H 'X-Airgap-Test: original' https://httpbin.org/headers
{
  "headers": {
    "Accept": "*/*",
    "Host": "httpbin.org",
    "User-Agent": "curl/8.5.0",
    "X-Airgap-Test": "rewritten-by-airgap",
    "X-Injected-By": "airgap"
  }
}
```

`httpbin` reflects the request headers back: `X-Airgap-Test` comes through as
`rewritten-by-airgap` (not `original`) and `X-Injected-By: airgap` was added —
proof the headers were rewritten inside the TLS session even though `curl`
validated the certificate.

## Platform support

- **Linux** — fully supported. `airgap` relies on mount namespaces and a FUSE
  overlay, which are Linux features.
- **macOS** — not yet, but incoming.

## Install

```
cargo install airgap
```

## Usage

```
airgap <program> [args...]
```

`airgap` runs `<program>` with `[args...]`, passing through argv, the
environment, and the working directory unchanged. When `<program>` exits,
`airgap` exits with the same code.

### Use with Claude / opencode

To always run your AI agent under `airgap`, alias it in your shell config
(`~/.bashrc`, `~/.zshrc`, ...):

```
alias claude="airgap claude"
alias opencode="airgap opencode"
```

Now `claude` (or `opencode`) transparently runs inside `airgap`.

### Use with npm

Run your package manager under `airgap` to guard against malicious install
scripts. Or alias it in your shell config:

```
alias npm="airgap npm"
```

## Security

If you want to report a security concern or ask a question, email
airgap@sauleau.com.
