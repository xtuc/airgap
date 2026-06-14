> Written and maintained by AI.

# airgap

A CLI wrapper that runs a target program inside its own mount namespace, with
specific files transparently replaced by FUSE-backed versions that only that
program (and its children) sees — the rest of the system is untouched.

## Usage

```
airgap [--allow-unknown-program] [--profile <name>] [--debug] <program> [args...]
```

Examples:

```
airgap claude                          # wrap a known AI agent (allowlisted)
airgap --allow-unknown-program myapp   # wrap anything else (opt-out)
```

By default `<program>` must be a program airgap has a
[profile](#per-program-profiles) for (AI agents `opencode`/`claude`, or the
package managers `npm`/`npx`/`yarn`/`pnpm`); the `--allow-unknown-program` flag
opts out of that check. See that section for the rationale.

`airgap` resolves `<program>`'s [profile](#per-program-profiles) (which also
gates which programs may run), then launches it with `[args...]`, sets up an
isolated mount namespace for it, and mounts a FUSE overlay over each protected
root — the working directory and the user's home directory (`$HOME`) — that
redacts sensitive files (see [Overridden files](#overridden-files)). For package
managers it additionally prompts before the program accesses a new file.
When `<program>` exits, `airgap` exits with the same exit code.

## Goals

- Run an arbitrary program transparently — argv and the environment are passed
  through unchanged, and the working directory is preserved (we re-enter the same
  path so it resolves through the overlay, but the child sees the same cwd).
- Redact sensitive files (any `.env`/`.env.*`, and private keys by content) so
  they are visible only as redacted versions to the wrapped program and its
  children, not changed for the host.
- Inspect and redact file contents on the fly, staying transparent to the
  wrapped program — nothing is written to its stdout/stderr.
- Support edits: when the child writes to a redacted file, persist real changes
  (edits, additions, deletions) back to the original, while keeping values it
  never saw (left at the placeholder) intact.
- Be a faithful wrapper: the parent's exit code mirrors the child's.

Non-goals (for now): a user-configurable rule set, redacting files outside the
protected roots (the working directory and `$HOME`), and supporting platforms
other than Linux.

## Overridden files

The set of files that get replaced by a FUSE-backed version. The rules are
hardcoded for now; more will be added.

- **Any file named `.env` or `.env.*`**, anywhere under a protected root
  (including subdirectories) — matched by basename, so `./.env`,
  `./.env.local`, `./svc/.env.production`, and `~/.env` are all caught.
  Unrelated dotfiles such as `.envrc` are **not** matched. Each is parsed and
  **redacted** (see [The `.env` handler](#the-env-handler)).
- **Any private key**, anywhere under a protected root — matched by content, not
  name: a file whose leading bytes are an SSH/PEM/PGP private-key header has its
  body **redacted** (see [The private-key handler](#the-private-key-handler)).

Matching is **dynamic, not a startup scan**: each protected root is mounted
through a FUSE overlay, so a file is matched when it is *accessed*. This means
files created **after** launch are caught too — a program that writes a new
`svc/.env` at runtime sees the redacted view when it reads it back. A tree with
no `.env` files is normal, not an error; those files are simply passed through.
There is no discovery walk and no "skipping override: No such file" noise.

## Design

### Process model

```
airgap (parent)
│
├─ resolve program profile        # reject unknown programs; pick gate (pre-flight)
├─ unshare(CLONE_NEWNS)           # new mount namespace
├─ make mounts private            # so our mounts don't leak to the host
├─ compute target roots           # {cwd, $HOME}, de-duplicated (see below)
│
├─ for each target root:          # the working dir and the user's home
│  ├─ open the root (O_PATH)      # captured BEFORE the mount shadows it
│  └─ mount FUSE overlay over it  # every file access in it flows through us
│
├─ chdir back into cwd            # re-resolve through the overlay (see below)
│
└─ fork/exec <program> [args...]  # child runs in the namespace, cwd = overlay
   │
   └─ on exit ────────────────►   parent reaps, exits with child's code
```

Everything happens on Linux. The tool will not run on macOS or other platforms.

**Target roots.** The protected roots are the working directory and the user's
home directory (`$HOME`, resolved through symlinks; dropped if unset or
unresolvable). If one nests inside the other — the common case of a cwd inside
`$HOME` — only the **outermost** is mounted, since its overlay already covers
everything beneath it. Disjoint roots (e.g. a cwd under `/tmp` and a home under
`/home`) each get their own overlay. Each overlay's backing fd is opened before
*its* mount, and because the surviving roots never nest, one overlay's mount can
never shadow another's fd.

The `chdir` step matters: our cwd fd is opened *before* the overlay is mounted,
so it still resolves to the underlying directory. Without re-entering the path,
the child would inherit that pre-mount cwd and relative accesses (`cat .env`)
would bypass the overlay. Re-entering the absolute path resolves it through the
freshly mounted overlay, which the child then inherits.

### Per-program profiles

`airgap` applies a **profile** to the target program — the unified place where
per-program policy lives (`src/profiles/`). `Profile` is a **trait**: it
*declares* what policy applies, one method per axis, and each concrete profile is
an implementation. A small provided method converts the declaration to runtime
machinery; the implementations only state policy.

```rust
trait Profile {
    fn redaction(&self) -> bool;                   // redact secret files on read
    fn directory_access(&self) -> DirectoryAccess; // file-access policy (gate or not)
    // provided: build the runtime gate from `directory_access()`
    fn directory_gate(&self, program: &OsStr) -> Option<Arc<dyn DirAccess>> { … }
}

enum DirectoryAccess {
    AllowAny,                  // no prompts; files may be accessed freely
    AskAllowList(Vec<String>), // ask before a file not covered by this allowlist
}

struct AiAgent; // opencode, claude
struct Npm;     // npm, npx, yarn, pnpm
```

- **`redaction`** is the baseline guarantee — `true` for every profile today —
  but it is part of the interface so it is explicit and a future redaction-free
  profile is expressible. When `false`, every file is passed through unchanged.
- **`directory_access`** is `AllowAny` for programs airgap trusts to roam the
  overlays freely, or `AskAllowList(preapproved)` for programs that must ask the
  user before reading a file not covered by the pre-approved list (files or
  directories, prefix-matched). `Npm` seeds the list with paths package managers
  routinely and benignly touch — `~/.npm/_logs`, `~/.npm/_cacache`,
  `~/.gitconfig`, `$CWD/node_modules`, `$CWD/package.json`, and
  `$CWD/package-lock.json`; broader seeding is future work. New policy axes (env
  scrubbing, network mediation) become further trait methods, so the profile
  stays the single declarative description of "what airgap does to this program".

The two implementations today:

| Program | impl | `redaction()` | `directory_access()` |
|---|---|---|---|
| `opencode`, `claude` (AI agents) | `AiAgent` | `true` | `AllowAny` |
| `npm`, `npx`, `yarn`, `pnpm` (package managers) | `Npm` | `true` | `AskAllowList([~/.npm/_logs, ~/.npm/_cacache, ~/.gitconfig, $CWD/node_modules, $CWD/package.json, $CWD/package-lock.json])` → [file-access gate](#file-access-gate-npm-and-friends) |
| anything else | — | — | rejected unless `--allow-unknown-program` |

`profile::resolve(program)` maps the executable basename to a boxed profile, and
that resolution **doubles as the allowlist**: an unrecognized program yields
`None`. The declarative profile is turned into runtime policy at launch:
`Profile::directory_gate(program)` builds the interactive gate (from
[`src/profiles/npm.rs`](#file-access-gate-npm-and-friends)) when `directory_access`
is `AskAllowList`, seeded with the pre-approved entries; the overlay is told
whether to redact. Keeping the description (the `Profile` trait) separate from
the mechanism (the FUSE overlay and the gate) is what lets the policy set grow
without touching the plumbing.

- **Matched by executable basename.** `airgap claude` and
  `airgap /usr/local/bin/claude` both match `claude`; the leading path is
  ignored. Matching is exact per component, so `claude-helper` does *not* match.
- **Pre-flight.** Resolution runs before `unshare`/`mount`, so a rejection is
  immediate, needs no privileges, and never leaves a half-built namespace. A
  rejected program exits non-zero with a message naming the recognized programs
  and the opt-out flag.
- **Opt-out.** `--allow-unknown-program` (a leading flag, before `<program>`)
  applies the *unrestricted* profile (redaction only, no gate) to any program.
  The flag is parsed only in airgap's own argument slot; anything after
  `<program>` — including a literal `--allow-unknown-program` — is passed through
  to the child untouched.
- **Explicit override.** `--profile <name>` forces a profile regardless of the
  program, bypassing name-based resolution. The names are `agent` (redaction
  only) and `npm` (redaction + file gate). This lets a program be run under
  a chosen policy — e.g. forcing the gate onto a tool that isn't a recognized
  package manager — and lets tests exercise the gate with a scriptable program
  like `cat` (`airgap --profile npm cat …`) instead of real `npm`.

**Program recognition is a guardrail, not a security boundary.** The basename
check is trivially satisfied by renaming or symlinking a binary to `claude`; its
purpose is to stop *accidental* misuse and to *select the right profile*, not to
resist an adversary who controls argv. The actual security property — that the
child can't read raw secrets — comes from the overlay and namespace. The profile
table is hardcoded for now; making it configurable is future work, tracked
alongside the configurable redaction rule set. Future policy axes (env scrubbing,
network mediation) extend the `Profile` struct.

### File-access gate (npm and friends)

Package managers run arbitrary third-party code at install time (`postinstall`
hooks), which is a well-documented secret-exfiltration vector (see
[`attack.md`](attack.md)). For those programs the profile adds a **file gate**:
the first time the program reads, writes, or creates a file not already covered
by a decision, the user is asked to allow or reject *that file*. The gate lives
in `src/profiles/npm.rs`; the overlay knows only a small `trait DirAccess { fn
allow(&self, path: &Path, access: Access) -> bool }`, so nothing
package-manager-specific leaks into the FUSE plumbing.

**Where it hooks.** Only **file operations** are gated, and the gate is told the
exact file and what kind of access it is (`Access::{Read, Write, Create}`):
`open` (read vs write from the flags) and `create`. Directory **listing**
(`readdir`) and path-resolution (`lookup`, `getattr` — i.e. `stat`) are *not*
gated: they expose names/metadata, not contents, so the asking is always about a
specific file. Gating the file operation rather than every ancestor lookup also
avoids prompting for the ancestor chain (`/home`, `/home/u`) on the way to a file
the program reads. Denial returns `EACCES`.

**The prompt names the exact file and operation:**

```
airgap: npm wants to read the file /home/u/.aws/credentials — allow? [y/N]
```

The grant is the **exact path** asked about — approving a file allows only that
file, so reading one file never silently grants the rest of `$HOME`.

**Decisions are matched by path prefix and cached for the run.** A *directory*
entry (pre-approved, below) covers every file beneath it; a *file* entry matches
only itself. Approvals and denials are both cached, so the same file isn't
re-prompted. The decision set is **in memory only**: it resets each run, with no
persisted grants to manage or revoke.

**Pre-approved paths** are allowed without ever prompting. They may be files or
directories, and are seeded with the paths package managers routinely and
benignly touch:

- `~/.npm/_logs` (directory) — npm's log output;
- `~/.npm/_cacache` (directory) — npm's content-addressable package cache;
- `~/.gitconfig` (file) — git identity npm reads;
- `$CWD/node_modules` (directory) — the project's installed dependencies;
- `$CWD/package.json` (file) — the project manifest;
- `$CWD/package-lock.json` (file) — the dependency lockfile.

Broader seeding (and making the list configurable) is future work. The
`--debug` flag logs each access the gate pre-allows (an allowlist hit) to
stderr — `airgap[debug]: pre-allowed read <path> (allowlist: <prefix>)` — to see
what a package manager touches silently and tune the list.

**Prompting.** The prompt is written to the controlling terminal (`/dev/tty`)
directly, not the child's stdio (which belongs to the wrapped program and is
observed verbatim by callers). The triggering FUSE operation — and thus the
child's syscall — blocks until the user answers. Any failure to prompt (no
controlling terminal, EOF) **fails closed**: the access is denied. The decision
lock is held across the prompt so concurrent requests don't interleave questions.

Both overlays (cwd and `$HOME`) share **one** gate instance, so a file is decided
once regardless of which overlay serves it, and decisions use absolute paths for
consistency across them.

### Mount namespace

Before mounting anything, `airgap` unshares the mount namespace with
`unshare(2)` and the `CLONE_NEWNS` flag (via the [`nix`](https://crates.io/crates/nix)
crate). This requires `CAP_SYS_ADMIN` (see [Privileges](#privileges)).

After unsharing, the root mount is remounted as private
(`mount(MS_REC | MS_PRIVATE)`) so that the overlay mounted in this namespace does
not propagate back to the host's namespace. This is the standard "private mount
namespace" setup.

The result: only `<program>` (and any children it spawns) sees the redacted
files. Other processes on the host continue to see the originals.

### Privileges

The mount-namespace and mount steps need `CAP_SYS_ADMIN`. Specifically:

| Step | Privilege needed |
|------|------------------|
| `unshare(CLONE_NEWNS)` (new mount namespace) | `CAP_SYS_ADMIN` |
| Remount root `MS_REC \| MS_PRIVATE` | `CAP_SYS_ADMIN` |
| Mount a FUSE overlay over each target root | `CAP_SYS_ADMIN`, or the setuid `fusermount3` helper |
| `fork`/`exec` the child | none |

There are two ways to obtain that capability.

#### Approach A — capability on the binary (current default)

Grant the binary `CAP_SYS_ADMIN` once, then run it as a normal user:

```
sudo setcap cap_sys_admin+ep "$(command -v airgap)"
airgap <program> [args...]
```

`+ep` makes the capability **e**ffective and **p**ermitted whenever the binary
runs, so no `sudo` is needed per invocation. This is the approach we use for now.
(Re-run `setcap` after each `cargo install`, since the capability is an attribute
of the file and is lost when the binary is replaced.)

If the capability is missing, `airgap` does not fail with a bare `EPERM` partway
through setup: it maps the `EPERM` from `unshare(CLONE_NEWNS)` to an actionable
message naming the exact `setcap` command for the running binary, then exits.

#### Approach B — unprivileged user namespace

Alternatively, create a user namespace first. An ordinary user can do this
(where distro policy allows — `kernel.unprivileged_userns_clone=1`, the default
on most modern distros), and inside it holds `CAP_SYS_ADMIN` over its own
namespaces — enough for the private remount and the mounts, with zero real
privileges.

The catch is identity: a fresh user namespace starts with no uid/gid mapping, so
the process would appear as `nobody`. We map the calling user back to itself.
The unprivileged rules allow writing **one line** to the map files covering
**only your own host uid** — which is exactly an identity map — without any
setuid helper:

```
unshare(CLONE_NEWUSER | CLONE_NEWNS)
write /proc/self/uid_map      "1000 1000 1"   # host uid 1000 → 1000 inside
write /proc/self/setgroups    "deny"          # required before gid_map
write /proc/self/gid_map      "1000 1000 1"
# now hold CAP_SYS_ADMIN inside → private remount + mounts
fork/exec child
```

Two gotchas: `gid_map` is rejected unless `setgroups` is set to `"deny"` first,
and the maps must be written before the mapped process relies on the new
identity. Mapping a *range* of uids or some *other* user would instead require
the setuid `newuidmap`/`newgidmap` helpers (from the `uidmap` package) reading
`/etc/subuid` / `/etc/subgid` — but the single-uid self-map we need does not.

### FUSE overlay

The FUSE filesystem is implemented with the
[`fuser`](https://crates.io/crates/fuser) crate — the actively maintained
successor to `fuse-rs`. It is a pure-Rust libfuse binding with a clean
trait-based API (`fuser::Filesystem`), supports background-session mounting, and
does not require the C `libfuse` development headers.

It is a **directory-level passthrough overlay**, not a set of per-file mounts —
one such overlay is mounted over each target root (the working directory and
`$HOME`). Every operation the child performs in a covered tree — `lookup`,
`getattr`, `open`, `read`, `write`, `readdir`, `create`, `unlink`, `rename`, … —
flows through that root's overlay. Ordinary files are proxied straight to the
real filesystem; only files that match a handler are transformed. Because
matching happens at access time, files created after launch are covered
automatically. Each overlay is an independent backend instance with its own
root fd; they share no state, so a `.env` is redacted identically whether it
lives under the cwd or under `$HOME`.

This overlay model is what makes interception **dynamic**, and it sidesteps the
hard-link bypass that per-file mounts have for paths *within the tree*: every
path into the overlaid subtree is routed through FUSE regardless of name.

**Reaching the real files without recursing.** A FUSE filesystem mounted over a
root would shadow the very files the backend needs to read. To avoid that,
`airgap` opens an `O_PATH` directory fd to each root **before** mounting that
root's overlay, and the backend performs all real I/O with `*at` syscalls
(`openat`, `fstatat`, `renameat`, …) relative to its fd. Those resolve against
the underlying directory, never back through the overlay. Because the surviving
roots never nest (see [Process model](#process-model)), mounting one overlay
can't shadow another's already-captured fd. Each fd is opened `O_CLOEXEC` so the
child can't inherit it.

So a program that opens any `.env` is served the redacted view by FUSE, while
every ordinary path it touches is proxied to the unmodified real file.

**Inodes and handles.** Inodes are assigned lazily: `lookup`/`create`/`mkdir`
intern the file's path (relative to the root fd) and hand back a stable inode;
`rename`/`unlink`/`rmdir` update that table. Each `open`/`create` allocates a file
handle holding either the real fd (passthrough) or the redacted bytes plus a
pending write buffer (`.env`).

**Truncation.** `open(..., O_TRUNC)` (e.g. rewriting a file in place) must reset
the `.env` pending buffer. The overlay requests the `FUSE_ATOMIC_O_TRUNC`
capability in `init` so the kernel delivers `O_TRUNC` in `open` (handled by
starting the pending buffer empty); a `setattr(size)` on an open `.env` handle is
also honored as a fallback.

**The FUSE layer stays as transparent as possible to the underlying file.** By
default each operation is proxied to the real backing file and returns its
genuine result. Timestamps and modes mirror the real file. The overlay emits no
output of its own: it must not write to the wrapped program's stdout/stderr,
since that output belongs to the child and is observed verbatim by callers.

A file may have a **content handler** that transforms what `read` returns. When
a handler is present, the served bytes are the transformed content and
`getattr`'s reported size is the length of that transformed content (not the real
file's), so reads are internally consistent. Files without a handler are pure
passthrough.

A handler may also support **writes**: when the child writes to an overridden
file, the handler decides how to persist the change back to the original. This is
a merge, not a blind copy, because what the child sees is the *redacted* view —
see the `.env` handler below for the exact rules. `getattr` reflects the current
served (redacted) content, and `setattr`/truncate operate on that view.

A handler is selected by either of two triggers:

- **By filename** — by basename, anywhere in a covered tree, e.g. `.env` or any
  `.env.*` variant (see [The `.env` handler](#the-env-handler)).
- **By content sniffing** — the backend inspects the original file's leading
  bytes and picks a handler if they match a known signature, e.g. an SSH private
  key (see [The private-key handler](#the-private-key-handler)).

Because each overlay covers a whole root, content sniffing applies to **every**
regular file the child reads under it, not just a fixed list — so a private key
under any name is caught. To keep this cheap, the backend sniffs only the first
bytes on `open`/`getattr`; it reads the whole file only once a handler has
matched.

### The `.env` handler

The `.env` handler redacts values on read and merges edits back on write. It is
selected by basename: the exact name `.env` or any `.env.*` variant (e.g.
`.env.local`, `.env.production`). Unrelated names like `.envrc` do not match.

**Read (redacted view).**

1. The backend reads the **original** file's bytes via its captured handle.
2. Those bytes are parsed with [`dotenvy`](https://crates.io/crates/dotenvy),
   parsing the *contents we already have* rather than letting the crate locate a
   file on disk — e.g. `dotenvy::from_read_iter(Cursor::new(bytes))`, which
   yields `(key, value)` pairs without touching the process environment.
3. The file is reconstructed with each value replaced by the **quoted**
   placeholder — one `KEY="<redacted value>"` line per entry — and that text is
   what FUSE returns. The value is quoted so that the embedded space is
   unambiguous and the line is valid `.env` syntax for any parser.

So a program reading `.env` sees the real keys but every value redacted. The
reconstruction is derived from the parsed pairs, so comments, blank lines, and
original formatting are not preserved — only the `KEY="<redacted value>"` lines.
The reported size matches this redacted text.

**Write (merge back to the original).** The child reads the redacted view, edits
it, and writes it back. We must persist real changes without clobbering the
values it never saw. On flush/release we parse the **written** buffer and diff it
against the redacted view, then rewrite the **original** file:

- **Unchanged value** — the written value is the placeholder `<redacted value>`.
  The placeholder always means "no change", so keep the original real value
  untouched.
- **Edited value** — the written value differs from the placeholder. Persist the
  new value verbatim to the original.
- **Added key** — a key not present in the original. Append it to the original
  with the value the child wrote.
- **Removed line** — a key present in the original but absent from the written
  buffer. **Delete it from the original file.**

So additions, edits, and deletions all propagate to the real `.env`; only keys
left at the placeholder are preserved as their original secret values.

**Fail closed.** If parsing fails on either side — a malformed original on read,
or a malformed buffer on write — the handler returns an **error** (e.g. `EIO`)
and, on write, leaves the original file **unmodified**. It must **never** fall
back to serving real contents on read, and must **never** persist a
partially-parsed/corrupt result on write. When redaction or a safe merge can't be
performed, the only acceptable outcomes are "redacted"/"persisted" or "error" —
never "raw" and never a corrupted original. This is the general rule for every
handler, not just `.env`.

### The private-key handler

Any file whose contents **start with** a private-key header is treated as a
secret and redacted, regardless of filename. Detection is by sniffing the leading
bytes of the original file for a header line such as:

- `-----BEGIN OPENSSH PRIVATE KEY-----` — covers ed25519 (and other modern
  OpenSSH-format keys).
- `-----BEGIN RSA PRIVATE KEY-----` — PEM/PKCS#1 RSA keys.
- `-----BEGIN PRIVATE KEY-----` / `-----BEGIN EC PRIVATE KEY-----` — generic
  PKCS#8 / EC keys.
- `-----BEGIN PGP PRIVATE KEY BLOCK-----` — PGP/GPG private keys, handled the
  same way as SSH keys.

When matched, the served content keeps the begin/end markers but replaces the
key body with the redaction placeholder:

```
-----BEGIN OPENSSH PRIVATE KEY-----
<redacted value>
-----END OPENSSH PRIVATE KEY-----
```

The begin/end marker lines are preserved verbatim from the original (so the key
*type* is still visible) and everything between them collapses to a single
`<redacted value>` line. As with `.env`, `getattr`'s size reflects this redacted
text.

### Bypass resistance (threat model)

The adversary is the **child process itself**: the goal is that it can never read
the true contents of a secret file, only the redacted version. The overlays cover
the working directory and `$HOME`, so every path *into a covered tree* —
relative, `..`, absolute, alternate hard-link names, symlinks within the tree —
resolves through FUSE. Path spelling is therefore not a bypass, and the per-file
hard-link problem (a second link under a different name) is closed for links that
stay inside a covered tree.

What the overlay covers well, and the residual gaps:

1. **The backend's root fds.** The backend holds an `O_PATH` fd to the real
   directory behind each overlay; `/proc/<pid>/fd/N` is a magic symlink that
   re-opens an inode *by reference*, ignoring mounts. If the child could reach the
   backend's `/proc` entry it could walk the real trees. Mitigation in place: the
   fds are `O_CLOEXEC` so the child can't inherit them. Not yet done: run the
   backend in a **separate PID namespace** (and/or as a uid the child can't
   `ptrace`/inspect) so its `/proc/<pid>/fd` isn't reachable.
2. **Privileged unmount / re-bind.** With the unprivileged-user-namespace
   approach (Approach B) the child can hold `CAP_SYS_ADMIN` over the mount
   namespace and could `umount` the overlay or bind the directory elsewhere,
   exposing the originals underneath. Mitigation: **lock** the overlay
   (`MNT_LOCKED`) in an outer namespace and run the child in a nested one where it
   can't unmount or move it. With Approach A the exec'd child is unprivileged (the
   file capability is not inherited across `exec`) and simply cannot unmount. *Not
   yet implemented.*
3. **Files outside the overlaid trees.** Only the working directory and `$HOME`
   are overlaid. A secret read by **absolute path outside** both (`/etc/...`, a
   sibling project dir, a system service's data dir), or a hard link from inside
   a covered tree to an inode also reachable by a path **outside** it, is not
   redacted. Note that the common sensitive locations — `~/.aws/credentials`,
   `~/.ssh/*`, `~/.config/...` — now fall **under** the `$HOME` overlay and are
   covered. Widening coverage further (more roots, or `/`) is future work.
4. **Name-based matching.** The `.env` handler matches by basename (`.env` and
   `.env.*`), so a copy or hard link under a *different* name (`cp .env
   secrets.txt`) inside a covered tree is not redacted (it is neither an `.env`
   name nor a sniffable key). Content-sniffed handlers (private keys) are immune
   to this; `.env` is not.

These residual gaps are known and tracked; the current implementation closes
path-spelling and in-tree hard-link bypasses and uses an `O_CLOEXEC` backend fd.
**Each future mitigation should ship with a test that attempts the bypass and
asserts it fails.**

### Lifecycle and exit code

1. Parent resolves `<program>`'s [profile](#per-program-profiles) (unless
   `--profile`/`--allow-unknown-program` was passed) and exits non-zero if the
   program is unrecognized, before any privileged setup. Then it unshares the
   mount namespace and sets mounts private.
2. Parent computes the target roots (`{cwd, $HOME}`, de-duplicated). For each, it
   opens an `O_PATH` fd to the root and mounts a FUSE overlay over it (on a
   background thread), then re-enters the cwd so it resolves through the overlay.
3. Parent spawns `<program>` with the passed-through arguments (inheriting the
   namespace and the overlay cwd).
4. Parent waits for the child.
5. When the child exits, the parent drops every FUSE session (which unmounts the
   overlays) and exits with the **same exit code** as the child (propagating
   signal-termination as `128 + signo`, matching shell convention).

## Testing

Every feature should be unit tested. In particular the content handlers are pure
functions over bytes — `original contents -> redacted contents` — so they are
tested directly without any FUSE mount or namespace setup:

- `.env` read handler: given sample `.env` contents, assert the output is the
  expected `KEY="<redacted value>"` lines and that all keys are preserved; given
  malformed contents, assert it **errors** rather than returning the raw bytes
  (fail closed).
- `.env` write/merge: given an original and an edited redacted buffer, assert the
  merge — placeholder values keep the original secret, changed values are
  persisted, added keys are appended, removed keys are deleted — and that a
  malformed buffer errors and leaves the original unmodified.
- private-key handler: given SSH (RSA, ed25519/OpenSSH, EC) and PGP private-key
  samples, assert detection fires and the output keeps the begin/end markers with
  a single `<redacted value>` body; given non-key content, assert it is left
  untouched.

Keeping redaction logic as pure functions separate from the FUSE/mount plumbing
is a deliberate design choice so the security-critical parts are cheap to test
exhaustively.

The command line is parsed with [`clap`](https://crates.io/crates/clap) (derive)
into a `Cli` struct: the program and its arguments are one `trailing_var_arg`
list so option parsing stops at the program — everything after it passes to the
child verbatim (including flags), while a mistyped airgap flag *before* the
program is still rejected and `airgap -- <prog>` handles a program whose name
starts with `-`. Parsing is tested via `Cli::try_parse_from`, and profile
resolution (`profile::resolve`/`by_name`, `npm::is_npm`) directly: recognized vs
rejected basenames, which programs get a gate, the `--allow-unknown-program`,
`--profile`, and `--debug` flags, flags-after-program passthrough, `--` handling,
and usage errors. The file gate's decision logic
(`DirGate`, via an injected asker) is unit-tested too: recursive allow/deny
caching by prefix, and that sibling subtrees are decided independently.

Because profile resolution is pre-flight (no privileges), rejection is covered
end-to-end without `CAP_SYS_ADMIN`: the integration tests assert an unrecognized
program is rejected and that the opt-out flag bypasses the check. The gate's
*enforcement* wiring is covered with the `--profile npm` override on a scriptable
program (`cat`) with no controlling terminal, so the prompt fails closed and the
access is denied with `EACCES` — no interactive input or real package manager
needed.

End-to-end behaviour (read redaction of `.env` and `.env.*`, redaction of a
secret in a `$HOME` disjoint from the cwd, dynamic runtime-created `.env`,
edit/add/delete persistence, passthrough, exit code) is covered by the
integration tests in `test/`, which run the real binary. The fixtures pin `$HOME`
to the per-test working directory so the suite never mounts over the real home of
whoever runs it; the disjoint-home test sets `$HOME` to a separate temp dir to
exercise the second overlay. They need `CAP_SYS_ADMIN`; equivalently the binary
can be driven under an unprivileged user namespace (`unshare -Urm`), which is how
the overlay is exercised without `setcap`.

## Dependencies

- [`fuser`](https://crates.io/crates/fuser) — FUSE filesystem implementation
  (the overlay implements `fuser::Filesystem`).
- [`nix`](https://crates.io/crates/nix) — `unshare`, `mount`, the `*at` syscalls
  (`openat`, `fstatat`, `renameat`, …) and directory iteration (`dir` feature)
  used by the overlay backend.
- [`dotenvy`](https://crates.io/crates/dotenvy) — parsing `.env` contents into
  key/value pairs (via `from_read_iter`, not file lookup).
- [`clap`](https://crates.io/crates/clap) (derive) — command-line parsing.
- [`anyhow`](https://crates.io/crates/anyhow) — error context in setup paths.

## Requirements

- Linux with FUSE support (`/dev/fuse`).
- `CAP_SYS_ADMIN`, obtained via either approach in [Privileges](#privileges):
  the capability set on the binary (default), or an unprivileged user namespace.

## Status

Working. The wrapped program is matched to a [profile](#per-program-profiles)
(AI agents `opencode`/`claude`; package managers `npm`/`npx`/`yarn`/`pnpm`),
which doubles as the allowlist — unrecognized programs are rejected unless
`--allow-unknown-program` or an explicit `--profile` is passed. The working
directory and the user's home directory are each mounted through a FUSE overlay
(collapsed to one mount when the cwd is inside `$HOME`): ordinary files pass
through to the real filesystem, any `.env`/`.env.*` (at any depth, including
files created after launch) is redacted via the `dotenvy`-based handler with
edits merged back, and any file beginning with an SSH/PEM/PGP private-key header
has its body redacted. Package managers additionally get an interactive
[file-access gate](#file-access-gate-npm-and-friends) (per-file grants,
in-memory, fail-closed, with a small pre-approved allowlist). Known residual
bypasses (backend `/proc`
fd, privileged unmount, files outside the overlaid trees, name-based `.env`
matching) are listed in [Bypass resistance](#bypass-resistance-threat-model).
