//! Network-namespace + user-space (smoltcp) TLS man-in-the-middle.
//!
//! Flow (see docs/mitm.md for the full write-up):
//!
//! 1. `setup()` — no privilege needed: load the header-rewrite rules and build
//!    the TLS machinery (an ephemeral CA + per-SNI cert minter for the client
//!    leg, native roots for the upstream leg), and write the CA bundle + a
//!    `resolv.conf` to bind-mount into the child.
//! 2. `start_netstack()` — after airgap has entered its (unprivileged) user
//!    namespace: a dedicated thread does `unshare(CLONE_NEWNET)` (per-thread!),
//!    creates a TUN as the netns default route, configures it in-process via
//!    rtnetlink, and runs a smoltcp TCP/IP stack over the TUN. airgap's other
//!    threads stay in the init netns, so upstream connections have real egress.
//! 3. `start_proxy()` — a thread in the *init* netns consumes the TCP byte
//!    streams smoltcp hands up: it terminates TLS with a cert minted for the SNI
//!    (trusted because the child gets our CA via the system store + env vars),
//!    rewrites request headers, opens a real TLS connection to the SNI host, and
//!    splices.
//! 4. The wrapped child joins the netns via a `setns` `pre_exec` hook, so only it
//!    (and its descendants) route through the TUN. DNS is answered by a stub in
//!    the stack (every A query resolves to the stack's own address; upstream is
//!    recovered from the TLS SNI, so the answer's value is irrelevant).
//!
//! The implementation is split across this module's children:
//!   - [`config`] — the YAML header-rewrite rules.
//!   - [`tun`]    — the TUN device + smoltcp phy `Device`.
//!   - [`netns`]  — network-namespace entry + rtnetlink interface config.
//!   - [`stack`]  — the smoltcp event loop (accepts TCP, pumps bytes, DNS).
//!   - [`stream`] — the async byte-stream bridge between stack and proxy.
//!   - [`dns`]    — the stub resolver.
//!   - [`proxy`]  — TLS termination + header rewriting.
//!
//! Scope (by design, see docs/mitm.md): first-request-per-connection header
//! rewriting, IPv4-only, SNI-only upstream.

use std::fs::OpenOptions;
use std::io::{self, Write as _};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use rustls::{ClientConfig, ServerConfig};
use tokio::sync::{Notify, mpsc};
use tokio_rustls::TlsAcceptor;

mod cert;
mod config;
mod dns;
mod netns;
mod proxy;
mod stack;
mod stream;
mod tun;

use config::Config;
use stream::NewConn;

/// The distro's system trust bundle (Debian/Ubuntu). We bind-mount an augmented
/// copy over this path inside the namespace so any TLS stack reading the system
/// store trusts our CA. See the bind-mount in main.rs.
pub const SYSTEM_CA_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";

// ---- Network-namespace / TUN parameters (shared across the submodules) -----

/// Name of the TUN interface created inside the child's netns.
const TUN_NAME: &str = "airgap0";
/// The stack's own address: it terminates every TCP connection and answers DNS.
/// Every A query resolves here, so all of the child's HTTPS lands on the stack.
const STACK_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
/// Address assigned to the TUN inside the netns (the child's source address).
const CHILD_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
/// /24, so `STACK_IP` is on-link for the child (no gateway/ARP needed on a TUN).
const PREFIX_LEN: u8 = 24;
/// The IPv6 counterpart of `STACK_IP` (a ULA): every AAAA query resolves here, so
/// IPv6 clients land on the stack just like IPv4 ones.
const STACK_IP6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
/// The IPv6 counterpart of `CHILD_IP`, assigned to the TUN.
const CHILD_IP6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
/// /64, so `STACK_IP6` is on-link for the child.
const PREFIX_LEN6: u8 = 64;
/// The port whose listeners we pre-seed, for the common `https://host` case. Any
/// other destination port the child dials (e.g. `https://host:5455`) is
/// discovered from its SYNs and gets a listener on demand. Every port is
/// TLS-terminated — airgap only inspects TLS, so plaintext on any port just fails
/// the handshake and is dropped, never forwarded.
const HTTPS_PORT: u16 = 443;

// ---- Mitm lifecycle --------------------------------------------------------

/// Everything the MitM needs to stay alive for the duration of the child.
pub struct Mitm {
    server_config: Arc<ServerConfig>,
    client_config: Arc<ClientConfig>,
    config: Arc<Config>,
    /// Path to the ephemeral CA cert (PEM) the child should trust. Handed to
    /// stacks that append a CA rather than read the system store (e.g. Node).
    pub ca_path: PathBuf,
    /// The system trust bundle *plus* our CA, to bind-mount over the real one
    /// (and to point at env vars for stacks that don't read the system store).
    pub ca_bundle_path: PathBuf,
    /// A `resolv.conf` pointing the child at the stack's stub resolver, to
    /// bind-mount over `/etc/resolv.conf` inside the namespace.
    pub resolv_path: PathBuf,
    /// The private directory holding the artifacts above (mode 0700); removed on
    /// drop. Keeping the files in one owned dir avoids racing on shared `/tmp`.
    tmp_dir: PathBuf,
    /// The child's network namespace (opened by the netstack thread); the child
    /// joins it via `setns` in a `pre_exec` hook.
    netns_fd: Option<OwnedFd>,
    /// Woken by the proxy side whenever it writes, so the stack loop reacts
    /// without busy-waiting. Handed to the netstack thread.
    wake: Arc<Notify>,
    /// Stack → proxy: newly accepted connections. `tx` is moved into the netstack
    /// thread by `start_netstack`; `rx` into the proxy thread by `start_proxy`.
    new_conn_tx: Option<mpsc::UnboundedSender<NewConn>>,
    new_conn_rx: Option<mpsc::UnboundedReceiver<NewConn>>,
}

/// Build the TLS machinery + on-disk artifacts. No privilege required — the
/// namespace/TUN work happens later in [`Mitm::start_netstack`], after airgap has
/// entered its user namespace (where it holds `CAP_NET_ADMIN`).
pub fn setup(config_path: &Path) -> Result<Mitm> {
    let config = Arc::new(Config::load(config_path)?);
    log::info!(
        "mitm: loaded {} rule(s) from {}",
        config.len(),
        config_path.display()
    );
    install_crypto_provider();

    let (ca_pem, minter) = cert::build_cert_minter().context("building ephemeral CA")?;
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(minter)),
    );
    let client_config = Arc::new(cert::build_upstream_client_config()?);

    // All artifacts live in one private, per-process directory (mode 0700) rather
    // than on shared `/tmp`, so another user can't pre-create or swap the files
    // we bind-mount / point trust env vars at.
    let tmp_dir = create_private_dir().context("creating MitM artifact directory")?;

    // Write the CA on its own (for append-style stacks like Node).
    let ca_path = tmp_dir.join("ca.pem");
    write_private_file(&ca_path, ca_pem.as_bytes()).context("writing CA pem")?;

    // Build "system trust bundle + our CA" to bind-mount over the system store.
    let mut bundle = std::fs::read(SYSTEM_CA_BUNDLE).unwrap_or_default();
    if !bundle.is_empty() && !bundle.ends_with(b"\n") {
        bundle.push(b'\n');
    }
    bundle.extend_from_slice(ca_pem.as_bytes());
    let ca_bundle_path = tmp_dir.join("ca-bundle.crt");
    write_private_file(&ca_bundle_path, &bundle).context("writing augmented CA bundle")?;

    // A resolv.conf pointing the child's resolver at the stack. The stub answers
    // both A (→ STACK_IP) and AAAA (→ STACK_IP6), so dual-stack clients reach the
    // stack over either family.
    let resolv_path = tmp_dir.join("resolv.conf");
    write_private_file(&resolv_path, format!("nameserver {STACK_IP}\n").as_bytes())
        .context("writing resolv.conf")?;

    let (tx, rx) = mpsc::unbounded_channel();
    Ok(Mitm {
        server_config,
        client_config,
        config,
        ca_path,
        ca_bundle_path,
        resolv_path,
        tmp_dir,
        netns_fd: None,
        wake: Arc::new(Notify::new()),
        new_conn_tx: Some(tx),
        new_conn_rx: Some(rx),
    })
}

impl Mitm {
    /// Spawn the netstack thread: it enters a fresh network namespace, creates
    /// and configures the TUN, and runs the smoltcp stack. Blocks until the netns
    /// is set up (or fails), then stashes the netns fd for the child to join.
    ///
    /// Must be called *after* airgap has entered its user namespace, so the
    /// thread inherits `CAP_NET_ADMIN` (the netns unshare is per-thread and does
    /// not have the single-threaded restriction that `CLONE_NEWUSER` does).
    pub fn start_netstack(&mut self) -> Result<()> {
        let tx = self.new_conn_tx.take().expect("start_netstack called once");
        let wake = self.wake.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<OwnedFd>>();

        std::thread::Builder::new()
            .name("airgap-netstack".into())
            .spawn(move || stack::netstack_thread(tx, wake, ready_tx))
            .context("spawning netstack thread")?;

        let netns_fd = ready_rx
            .recv()
            .context("netstack thread exited before signalling readiness")??;
        self.netns_fd = Some(netns_fd);
        Ok(())
    }

    /// Spawn the proxy thread in the *init* netns: it consumes the TCP streams the
    /// stack accepts, terminates TLS, rewrites, and forwards upstream (whose
    /// connections therefore use the host's real networking).
    pub fn start_proxy(&mut self) -> Result<()> {
        let mut rx = self.new_conn_rx.take().expect("start_proxy called once");
        let server_config = self.server_config.clone();
        let client_config = self.client_config.clone();
        let config = self.config.clone();

        std::thread::Builder::new()
            .name("airgap-mitm".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build tokio runtime");
                rt.block_on(async move {
                    let acceptor = TlsAcceptor::from(server_config);
                    while let Some(nc) = rx.recv().await {
                        let acceptor = acceptor.clone();
                        let cc = client_config.clone();
                        let cfg = config.clone();
                        tokio::task::spawn(async move {
                            if let Err(e) =
                                proxy::handle_conn(nc.stream, nc.port, acceptor, cc, cfg).await
                            {
                                log::warn!("mitm: connection error: {e:#}");
                            }
                        });
                    }
                });
            })
            .context("spawning proxy thread")?;
        Ok(())
    }

    /// A `pre_exec` closure for the child. It (1) joins the network namespace via
    /// `setns`, (2) unshares a private mount namespace, and (3) bind-mounts the
    /// stub `resolv.conf` over `/etc/resolv.conf` — child-only, so airgap's own
    /// threads (the proxy) keep the host resolver for upstream DNS.
    ///
    /// Async-signal-safe: only pre-opened fds, pre-built `CString`s, and bare
    /// syscalls; no allocation.
    pub fn child_setup_hook(
        &self,
    ) -> Result<impl FnMut() -> io::Result<()> + Send + Sync + 'static> {
        let fd: RawFd = self
            .netns_fd
            .as_ref()
            .ok_or_else(|| anyhow!("netns not set up; call start_netstack first"))?
            .as_raw_fd();
        let resolv_src = std::ffi::CString::new(self.resolv_path.as_os_str().as_bytes())
            .context("resolv path has a NUL byte")?;
        let resolv_dst = c"/etc/resolv.conf".to_owned();

        Ok(move || {
            // SAFETY: all args are valid and outlive the calls; these syscalls
            // are async-signal-safe. The fds/strings were prepared pre-fork.
            unsafe {
                // (1) Join the child's network namespace.
                if libc::setns(fd, libc::CLONE_NEWNET) != 0 {
                    return Err(io::Error::last_os_error());
                }
                // (2) Private mount namespace, so the resolv.conf override below
                //     is visible only to the child (airgap's mount tree is already
                //     MS_PRIVATE, so nothing propagates back).
                if libc::unshare(libc::CLONE_NEWNS) != 0 {
                    return Err(io::Error::last_os_error());
                }
                // (3) Point the child's resolver at the stub. Best-effort: if the
                //     bind fails the child just can't resolve names — not fatal.
                libc::mount(
                    resolv_src.as_ptr(),
                    resolv_dst.as_ptr(),
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                );
            }
            Ok(())
        })
    }
}

impl Drop for Mitm {
    fn drop(&mut self) {
        // Best-effort cleanup of the on-disk artifacts. The netns and its threads
        // die with the process.
        let _ = std::fs::remove_dir_all(&self.tmp_dir);
    }
}

fn install_crypto_provider() {
    // Idempotent; ignore "already installed".
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Create an owned, per-process directory (mode 0700) under the system temp dir
/// for the MitM artifacts. A stale directory from a previous run with the same PID
/// is removed first.
fn create_private_dir() -> Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("airgap-mitm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("restricting permissions on {}", dir.display()))?;
    Ok(dir)
}

/// Write `data` to `path`, creating it exclusively (`O_EXCL`) with mode 0600.
/// The exclusive create refuses to follow a pre-existing file or symlink.
fn write_private_file(path: &Path, data: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(data)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}
