> Written and maintained by AI.

# airgap

A CLI wrapper that runs a target program inside its own mount namespace, with
specific files transparently replaced by FUSE-backed versions that only that
program (and its children) sees — the rest of the system is untouched.

## Usage

```
airgap <program> [args...]
```

Example:

```
airgap myapp --config ./config
```

`airgap` launches `<program>` with `[args...]`, sets up an isolated mount
namespace for it, and mounts a FUSE overlay over the working directory that
redacts sensitive files (see [Overridden files](#overridden-files)). When
`<program>` exits, `airgap` exits with the same exit code.

## Goals

- Run an arbitrary program transparently — argv and the environment are passed
  through unchanged, and the working directory is preserved (we re-enter the same
  path so it resolves through the overlay, but the child sees the same cwd).
- Redact sensitive files (any `.env`, and private keys by content) so they are
  visible only as redacted versions to the wrapped program and its children, not
  changed for the host.
- Inspect and redact file contents on the fly, staying transparent to the
  wrapped program — nothing is written to its stdout/stderr.
- Support edits: when the child writes to a redacted file, persist real changes
  (edits, additions, deletions) back to the original, while keeping values it
  never saw (left at the placeholder) intact.
- Be a faithful wrapper: the parent's exit code mirrors the child's.

Non-goals (for now): a user-configurable rule set, redacting files outside the
working directory, and supporting platforms other than Linux.

## Overridden files

The set of files that get replaced by a FUSE-backed version. The rules are
hardcoded for now; more will be added.

- **Any file named `.env`**, anywhere under the working directory (including
  subdirectories) — matched by basename, so `./.env`, `./svc/.env`, and
  `./a/b/c/.env` are all caught. Each is parsed and **redacted** (see
  [The `.env` handler](#the-env-handler)).
- **Any private key**, anywhere under the working directory — matched by
  content, not name: a file whose leading bytes are an SSH/PEM/PGP private-key
  header has its body **redacted** (see
  [The private-key handler](#the-private-key-handler)).

Matching is **dynamic, not a startup scan**: the whole working directory is
mounted through a FUSE overlay, so a file is matched when it is *accessed*. This
means files created **after** launch are caught too — a program that writes a new
`svc/.env` at runtime sees the redacted view when it reads it back. A working tree
with no `.env` files is normal, not an error; those files are simply passed
through. There is no discovery walk and no "skipping override: No such file"
noise.

## Design

### Process model

```
airgap (parent)
│
├─ unshare(CLONE_NEWNS)           # new mount namespace
├─ make mounts private            # so our mounts don't leak to the host
├─ open the working dir (O_PATH)  # captured BEFORE the mount shadows it
├─ mount FUSE overlay over cwd    # every file access now flows through us
├─ chdir back into cwd            # re-resolve through the overlay (see below)
│
└─ fork/exec <program> [args...]  # child runs in the namespace, cwd = overlay
   │
   └─ on exit ────────────────►   parent reaps, exits with child's code
```

Everything happens on Linux. The tool will not run on macOS or other platforms.

The `chdir` step matters: our cwd fd is opened *before* the overlay is mounted,
so it still resolves to the underlying directory. Without re-entering the path,
the child would inherit that pre-mount cwd and relative accesses (`cat .env`)
would bypass the overlay. Re-entering the absolute path resolves it through the
freshly mounted overlay, which the child then inherits.

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
| Mount the FUSE overlay over the cwd | `CAP_SYS_ADMIN`, or the setuid `fusermount3` helper |
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

It is a **directory-level passthrough overlay** mounted over the whole working
directory, not a set of per-file mounts. Every operation the child performs in
that tree — `lookup`, `getattr`, `open`, `read`, `write`, `readdir`, `create`,
`unlink`, `rename`, … — flows through the overlay. Ordinary files are proxied
straight to the real filesystem; only files that match a handler are transformed.
Because matching happens at access time, files created after launch are covered
automatically.

This overlay model is what makes interception **dynamic**, and it sidesteps the
hard-link bypass that per-file mounts have for paths *within the tree*: every
path into the overlaid subtree is routed through FUSE regardless of name.

**Reaching the real files without recursing.** A FUSE filesystem mounted over the
working directory would shadow the very files the backend needs to read. To avoid
that, `airgap` opens an `O_PATH` directory fd to the working directory **before**
mounting the overlay over it, and the backend performs all real I/O with `*at`
syscalls (`openat`, `fstatat`, `renameat`, …) relative to that fd. Those resolve
against the underlying directory, never back through the overlay. The fd is opened
`O_CLOEXEC` so the child can't inherit it.

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

- **By filename** — by basename, anywhere in the tree, e.g. any `.env` (see
  [The `.env` handler](#the-env-handler)).
- **By content sniffing** — the backend inspects the original file's leading
  bytes and picks a handler if they match a known signature, e.g. an SSH private
  key (see [The private-key handler](#the-private-key-handler)).

Because the overlay covers the whole working directory, content sniffing applies
to **every** regular file the child reads in the tree, not just a fixed list — so
a private key under any name is caught. To keep this cheap, the backend sniffs
only the first bytes on `open`/`getattr`; it reads the whole file only once a
handler has matched.

### The `.env` handler

The `.env` handler redacts values on read and merges edits back on write.

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
the true contents of a secret file, only the redacted version. The overlay covers
the whole working directory, so every path *into that tree* — relative, `..`,
absolute, alternate hard-link names, symlinks within the tree — resolves through
FUSE. Path spelling is therefore not a bypass, and the per-file hard-link problem
(a second link under a different name) is closed for links that stay inside the
tree.

What the overlay covers well, and the residual gaps:

1. **The backend's root fd.** The backend holds an `O_PATH` fd to the real
   working directory; `/proc/<pid>/fd/N` is a magic symlink that re-opens an inode
   *by reference*, ignoring mounts. If the child could reach the backend's `/proc`
   entry it could walk the real tree. Mitigation in place: the fd is `O_CLOEXEC`
   so the child can't inherit it. Not yet done: run the backend in a **separate
   PID namespace** (and/or as a uid the child can't `ptrace`/inspect) so its
   `/proc/<pid>/fd` isn't reachable.
2. **Privileged unmount / re-bind.** With the unprivileged-user-namespace
   approach (Approach B) the child can hold `CAP_SYS_ADMIN` over the mount
   namespace and could `umount` the overlay or bind the directory elsewhere,
   exposing the originals underneath. Mitigation: **lock** the overlay
   (`MNT_LOCKED`) in an outer namespace and run the child in a nested one where it
   can't unmount or move it. With Approach A the exec'd child is unprivileged (the
   file capability is not inherited across `exec`) and simply cannot unmount. *Not
   yet implemented.*
3. **Files outside the overlaid tree.** Only the working directory is overlaid. A
   secret read by **absolute path outside** the cwd (`$HOME/.aws/credentials`,
   `/etc/...`), or a hard link from inside the tree to an inode also reachable by
   a path **outside** it, is not redacted. Widening coverage (overlay more roots,
   or `/`) is future work.
4. **Name-based matching.** The `.env` handler matches by basename, so a copy or
   hard link under a *different* name (`cp .env .env.bak`) inside the tree is not
   redacted (it is neither named `.env` nor a sniffable key). Content-sniffed
   handlers (private keys) are immune to this; `.env` is not.

These residual gaps are known and tracked; the current implementation closes
path-spelling and in-tree hard-link bypasses and uses an `O_CLOEXEC` backend fd.
**Each future mitigation should ship with a test that attempts the bypass and
asserts it fails.**

### Lifecycle and exit code

1. Parent unshares the mount namespace and sets mounts private.
2. Parent opens an `O_PATH` fd to the working directory, then mounts the FUSE
   overlay over the cwd (on a background thread) and re-enters the cwd so it
   resolves through the overlay.
3. Parent spawns `<program>` with the passed-through arguments (inheriting the
   namespace and the overlay cwd).
4. Parent waits for the child.
5. When the child exits, the parent drops the FUSE session (which unmounts the
   overlay) and exits with the **same exit code** as the child (propagating
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

End-to-end behaviour (read redaction, dynamic runtime-created `.env`, edit/add/
delete persistence, passthrough, exit code) is covered by the integration tests
in `test/`, which run the real binary. They need `CAP_SYS_ADMIN`; equivalently
the binary can be driven under an unprivileged user namespace (`unshare -Urm`),
which is how the overlay is exercised without `setcap`.

## Dependencies

- [`fuser`](https://crates.io/crates/fuser) — FUSE filesystem implementation
  (the overlay implements `fuser::Filesystem`).
- [`nix`](https://crates.io/crates/nix) — `unshare`, `mount`, the `*at` syscalls
  (`openat`, `fstatat`, `renameat`, …) and directory iteration (`dir` feature)
  used by the overlay backend.
- [`dotenvy`](https://crates.io/crates/dotenvy) — parsing `.env` contents into
  key/value pairs (via `from_read_iter`, not file lookup).

## Requirements

- Linux with FUSE support (`/dev/fuse`).
- `CAP_SYS_ADMIN`, obtained via either approach in [Privileges](#privileges):
  the capability set on the binary (default), or an unprivileged user namespace.

## Status

Working. The working directory is mounted through a FUSE overlay: ordinary files
pass through to the real filesystem, any `.env` (at any depth, including files
created after launch) is redacted via the `dotenvy`-based handler with edits
merged back, and any file beginning with an SSH/PEM/PGP private-key header has its
body redacted. Known residual bypasses (backend `/proc` fd, privileged unmount,
files outside the tree, name-based `.env` matching) are listed in
[Bypass resistance](#bypass-resistance-threat-model).
