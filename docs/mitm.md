# Network-namespace + user-space TLS man-in-the-middle

> Written and maintained by AI.

Opt-in via `--mitm`: SNI-only, first-request-per-connection header rewriting,
over both IPv4 and IPv6. It implements the "mediate the network" capability —
blocking/faking IMDS, Vault, and exfil endpoints.

## What it does

Run any `https://` client under `airgap` (with `--mitm`) and its requests are
transparently intercepted, decrypted, **rewritten per a YAML rule set** (match on
the `Host` header, override/add headers), re-encrypted, and forwarded to the real
server. The client validates TLS normally — it just trusts an ephemeral CA we
hand it for the duration of the run.

Unlike the earlier eBPF prototype, this needs **no root**: the interception runs
entirely in a private network namespace + a bundled user-space TCP/IP stack, both
reachable from the same unprivileged user namespace `airgap` already uses for FUSE
redaction.

## Configuration

Rules live in the YAML file passed as `--mitm-config <path>`, which `--mitm`
requires: no default location, no search path, and a missing or malformed file
is an error rather than a silent "no rules". The demo uses the in-repo
`./mitm.yaml`:

```yaml
rules:
  - host: httpbin.org            # matched exactly against the request's Host
    headers:                     #   header (case-insensitive; no subdomains)
      X-Airgap-Test: rewritten-by-airgap   # override if present, add if absent
      X-Injected-By: airgap
  - host: example.com
    headers:
      X-Env: staging
```

Matching: `Host` is lowercased and its port stripped, then compared **exactly**
to each rule's `host` (subdomains do not match); the **first** match wins. For
that rule, each listed header is set on the request (replacing any existing
header of that name, or added), and **every other header the client sent is
preserved**. A request whose host matches no rule is forwarded byte-for-byte. A
missing or malformed config file fails MitM setup (logged as `MitM disabled: …`,
the run continues with FUSE redaction only) rather than quietly rewriting
nothing.

## Architecture

The wrapped child lives in its own network namespace whose only route is a TUN
device; a bundled [smoltcp](https://github.com/smoltcp-rs/smoltcp) stack (on a
thread that joins that netns) drives the TUN, while airgap's proxy thread stays
in the *init* netns, so the proxy's upstream connections still use the host's
real network.

```
  child (own netns; default route → TUN)                   airgap process
    │  connect() example.com:443            ┌───────────────── init netns ──────────────┐
    │  (resolves to 10.0.0.1 via stub DNS)  │                                            │
    ▼                                        │  netstack thread (in the child's netns):  │
  ┌─────────┐   raw IP packets   ┌──────────┤   smoltcp over the TUN fd                  │
  │  TUN     │◄──────────────────►│ TUN fd   │   ├─ TCP :443 → async byte stream ───┐     │
  │ airgap0  │                    └──────────┤   ├─ TCP :80  → fails TLS, dropped   │     │
  └─────────┘                                │   └─ UDP :53  → stub DNS (→10.0.0.1) │     │
                                             │                                     │      │
                                             │  proxy thread (init netns):  ◄──────┘      │
                                             │   ├─ terminate TLS: mint a cert for the SNI│
                                             │   ├─ read request head, rewrite headers    │
                                             │   ├─ real TLS connect to <SNI>:443 (host   │
                                             │   │  networking, real DNS)                 │
                                             │   └─ copy_bidirectional                    │
                                             └────────────────────────────────────────────┘
```

### Key design choices (and shortcuts)

- **Per-thread network namespace.** Network-namespace membership is per-thread,
  so `airgap` keeps its main + proxy threads in the init netns (real upstream
  egress) while a single *netstack* thread does `unshare(CLONE_NEWNET)` and owns
  the TUN. The child joins that netns via a `setns` `pre_exec` hook. No `veth`, no
  host-side `CAP_NET_ADMIN`, no `slirp`/`pasta` — the stack *is* the egress path
  for the child, and the proxy bridges it to the real network.
- **Bundled user-space stack.** smoltcp terminates the child's TCP connections
  over the TUN and hands each one up as an async byte stream (`SmoltcpStream`,
  an `AsyncRead`/`AsyncWrite` backed by channels the stack services). The rustls
  MitM core is unchanged from the eBPF version; only the front-end (where the
  client byte stream comes from) changed.
- **SNI-only upstream.** The real upstream is recovered from the TLS ClientHello
  SNI, not from the original destination. A **stub DNS resolver** in the stack
  answers every `A` query with the stack's own IPv4 address (`10.0.0.1`) and
  every `AAAA` with its IPv6 address (`fd00::1`), so all name-based HTTPS lands on
  the stack over either family; the SNI then names the real host.
- **Only TLS is inspected; plaintext is dropped, never passed through.** Every
  accepted connection is handed to the TLS acceptor regardless of port, so a
  plaintext client (e.g. `http://…` on `:80`) just fails the handshake and the
  connection is dropped — nothing is ever forwarded in the clear. Only `:443` is
  pre-seeded with listeners; any other port the child dials gets one on demand
  (discovered from its SYN) and is TLS-terminated the same way. This keeps
  uninspectable plaintext from silently escaping the sandbox.
- **TLS trust via the on-disk store + env vars.** We build an augmented bundle
  (the host's real roots **+** our ephemeral CA) and bind-mount it over
  `/etc/ssl/certs/ca-certificates.crt` inside `airgap`'s mount namespace. We also
  set `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE` (to the augmented
  bundle) and `NODE_EXTRA_CA_CERTS` (to the bare CA) for the child — these
  **override** any inherited value (e.g. a VPN's `SSL_CERT_FILE`, which would
  otherwise win over the bind-mount). Still **not** covered: Java (own keystore),
  Rust `rustls`+webpki-roots (compiled-in), and any cert-pinning client.
- **Child-scoped resolver.** The child's `/etc/resolv.conf` is pointed at the
  stub (`nameserver 10.0.0.1`) via a bind-mount in the **child's own** mount
  namespace (unshared in the `pre_exec` hook), so `airgap`'s proxy thread keeps
  the host resolver for upstream lookups.
- **Ordering.** The TLS machinery is built before entering namespaces (it spawns
  no threads, so the single-threaded `unshare(CLONE_NEWUSER)` still works). The
  netns/TUN/stack come up afterwards, once we hold `CAP_NET_ADMIN` in the user
  namespace.

## Requirements

- Linux with `/dev/net/tun`.
- Unprivileged user namespaces enabled (the same prerequisite as `airgap`'s FUSE
  redaction) **or** the binary granted `CAP_SYS_ADMIN`/`CAP_NET_ADMIN`. No `sudo`.
- No special build toolchain: plain **`cargo build`** (stable). The eBPF crate,
  `bpf-linker`, and the nightly/`rust-src` requirement are gone.

## Build & run

```
cargo build

# --mitm turns interception on (it's off by default) and requires a config path.
# curl isn't a "recognized" airgap program, so pass --allow-unknown-program.
./target/debug/airgap --mitm --mitm-config ./mitm.yaml --allow-unknown-program \
    curl -H 'X-Airgap-Test: original' https://httpbin.org/headers
```

Expected: `httpbin` reflects the request headers, and `X-Airgap-Test` comes back
as **`rewritten-by-airgap`** (not `original`) — proof the header was rewritten
inside the TLS session. Without airgap, it would read `original`.

Without `--mitm` interception is skipped entirely. With `--mitm` but no way to
create the netns (unprivileged userns disabled and no capability), airgap logs
`MitM disabled: …` and continues with only its FUSE redaction.

Logs go to `$XDG_STATE_HOME/airgap/airgap.log` (else `~/.local/state/...`);
`--debug` raises the level.

## Known limitations / TODO

- **Name-based (SNI) HTTPS only.** The stub DNS points every name at the stack,
  so name-based `https://` is intercepted; a client connecting to a **literal
  IP** on `:443` (e.g. IMDS `169.254.169.254`) is routed to the TUN but dropped
  by the stack (it only owns its own addresses) rather than intercepted — a
  regression from the eBPF path, which rewrote any `:443` destination. For the
  IMDS/Vault blocking goal this is acceptable (drop ≈ block), but it should be
  revisited.
- One-request-per-connection: only the first request head on a connection is
  rewritten. Matched hosts therefore get `Connection: close` forced on that
  request, so the child reconnects (and gets rewritten) for the next one —
  correct, at the cost of a TLS handshake per request. Unmatched hosts keep
  keep-alive. A rule that sets `Connection` itself overrides this. Two gaps
  remain: a client that pipelines request 2 before reading the response, and an
  upstream that ignores `close`, both fall back to the unrewritten passthrough.
  Forcing `close` also drops any `Connection: Upgrade`, so WebSocket upgrades to
  a *matched* host won't work.
- No ALPN/HTTP/2 handling — relies on falling back to HTTP/1.1.
- The stack loop wakes on a timer + reactor readiness rather than a fully
  event-driven epoll integration; fine for now, not tuned for throughput.
- Rules match on host only (no path/method matching yet) and only rewrite
  request headers (not response headers or bodies). The eventual goal is richer
  policy (block/allow/rewrite by host+path), wired to the profile system.
