//! The smoltcp event loop: it drives the TUN, accepts the child's TCP
//! connections and hands each to the proxy as an async byte stream, answers stub
//! DNS, and pumps bytes both ways between smoltcp sockets and the proxy channels.

use std::collections::{BTreeSet, HashMap};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::io::unix::AsyncFd;
use tokio::sync::{Notify, mpsc};

use super::dns::StubDns;
use super::netns::{configure_interface, enter_new_netns, open_thread_netns};
use super::stream::{self, NewConn, StackChannel};
use super::tun::Tun;
use super::{HTTPS_PORT, PREFIX_LEN, PREFIX_LEN6, STACK_IP, STACK_IP6, TUN_NAME};

/// How many idle listening sockets to keep per port (accept backlog).
const LISTEN_BACKLOG: usize = 8;
/// Bytes moved between smoltcp and a connection's channel per step.
const CHUNK: usize = 2048;

/// Entry point for the netstack thread. Enters a new netns, creates the TUN,
/// configures the interface, signals readiness (handing the netns fd back), then
/// runs the stack forever.
///
/// Must be called *after* airgap has entered its user namespace, so the thread
/// inherits `CAP_NET_ADMIN` (the netns unshare is per-thread and does not have the
/// single-threaded restriction that `CLONE_NEWUSER` does).
pub(super) fn netstack_thread(
    new_conn_tx: mpsc::UnboundedSender<NewConn>,
    wake: Arc<Notify>,
    ready_tx: std::sync::mpsc::Sender<Result<OwnedFd>>,
) {
    if let Err(e) = enter_new_netns() {
        let _ = ready_tx.send(Err(e));
        return;
    }
    let tun = match Tun::create(TUN_NAME) {
        Ok(t) => t,
        Err(e) => {
            let _ = ready_tx.send(Err(e));
            return;
        }
    };
    let netns_fd = match open_thread_netns() {
        Ok(fd) => fd,
        Err(e) => {
            let _ = ready_tx.send(Err(e));
            return;
        }
    };

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let _ = ready_tx.send(Err(anyhow::anyhow!("building netstack runtime: {e}")));
            return;
        }
    };
    rt.block_on(async move {
        if let Err(e) = configure_interface().await {
            let _ = ready_tx.send(Err(e));
            return;
        }
        let stack = match Stack::new(tun, new_conn_tx, wake) {
            Ok(s) => s,
            Err(e) => {
                let _ = ready_tx.send(Err(e));
                return;
            }
        };
        // Netns is fully set up; the child may now join it.
        if ready_tx.send(Ok(netns_fd)).is_err() {
            return; // main gave up
        }
        stack.run().await;
    });
}

/// The per-connection bookkeeping the stack keeps for a promoted TCP socket.
struct NetConn {
    /// Stack → proxy. `None` once the peer's FIN has been surfaced (EOF).
    to_app: Option<mpsc::Sender<Vec<u8>>>,
    /// Proxy → stack.
    from_app: mpsc::Receiver<Vec<u8>>,
    /// Bytes we pulled from `from_app` but smoltcp's tx buffer couldn't take yet.
    pending_out: Option<Vec<u8>>,
    /// The proxy dropped its writer; we should FIN once `pending_out` drains.
    app_write_closed: bool,
    sent_fin: bool,
    /// Set once the connection has been established. Until then `!may_recv()`
    /// just means "handshake not finished" (SynReceived), not peer-FIN — so we
    /// must not mistake it for EOF and tear down the proxy's read side.
    established: bool,
}

impl NetConn {
    fn new(channel: StackChannel) -> NetConn {
        NetConn {
            to_app: Some(channel.to_app),
            from_app: channel.from_app,
            pending_out: None,
            app_write_closed: false,
            sent_fin: false,
            established: false,
        }
    }
}

/// The whole user-space stack: the smoltcp interface over the TUN, the sockets it
/// owns (DNS + TCP listeners + promoted connections), and the plumbing to the
/// proxy. Built by [`Stack::new`] and driven to completion by [`Stack::run`].
struct Stack {
    iface: Interface,
    device: Tun,
    /// Watches the TUN fd for readability so the loop sleeps instead of spinning.
    afd: AsyncFd<TunFd>,
    sockets: SocketSet<'static>,
    dns: StubDns,
    listeners: Vec<(SocketHandle, u16)>,
    conns: HashMap<SocketHandle, NetConn>,
    /// Ports we keep listeners on: the pre-seeded 443 plus any the child dials.
    wanted_ports: BTreeSet<u16>,
    new_conn_tx: mpsc::UnboundedSender<NewConn>,
    /// Woken by the proxy side whenever it writes, so the loop reacts promptly.
    wake: Arc<Notify>,
}

impl Stack {
    fn new(
        mut device: Tun,
        new_conn_tx: mpsc::UnboundedSender<NewConn>,
        wake: Arc<Notify>,
    ) -> Result<Stack> {
        let mut iface = Interface::new(
            IfaceConfig::new(HardwareAddress::Ip),
            &mut device,
            SmolInstant::now(),
        );
        let mut addr_ok = true;
        iface.update_ip_addrs(|addrs| {
            addr_ok = addrs
                .push(IpCidr::new(IpAddress::from(STACK_IP), PREFIX_LEN))
                .is_ok()
                && addrs
                    .push(IpCidr::new(IpAddress::from(STACK_IP6), PREFIX_LEN6))
                    .is_ok();
        });
        if !addr_ok {
            bail!("assigning the stack's addresses to the interface");
        }

        let afd = AsyncFd::new(TunFd(device.as_raw_fd()))
            .context("registering the TUN fd with the reactor")?;

        let mut sockets = SocketSet::new(Vec::new());
        let dns = StubDns::add(&mut sockets)?;

        let mut stack = Stack {
            iface,
            device,
            afd,
            sockets,
            dns,
            listeners: Vec::new(),
            conns: HashMap::new(),
            wanted_ports: BTreeSet::from([HTTPS_PORT]),
            new_conn_tx,
            wake,
        };
        stack.ensure_listeners();
        Ok(stack)
    }

    /// Run the event loop until the process exits.
    async fn run(mut self) {
        loop {
            // Read everything pending off the TUN first, learning any new
            // destination port so its listener is in place before smoltcp handles
            // the SYN below.
            self.device.drain(&mut self.wanted_ports);
            self.ensure_listeners();

            let now = SmolInstant::now();
            self.iface.poll(now, &mut self.device, &mut self.sockets);
            self.dns.service(&mut self.sockets);
            self.promote_listeners();
            self.service_conns();
            self.ensure_listeners();
            // Flush anything the servicing queued for egress.
            self.iface
                .poll(SmolInstant::now(), &mut self.device, &mut self.sockets);

            let timeout = self
                .iface
                .poll_delay(SmolInstant::now(), &self.sockets)
                .map(|d| Duration::from_micros(d.total_micros()))
                .unwrap_or(Duration::from_millis(100));

            tokio::select! {
                r = self.afd.readable() => {
                    if let Ok(mut guard) = r {
                        guard.clear_ready();
                    }
                }
                _ = self.wake.notified() => {}
                _ = tokio::time::sleep(timeout) => {}
            }
        }
    }

    /// Ensure `LISTEN_BACKLOG` idle listeners exist for each wanted port.
    fn ensure_listeners(&mut self) {
        for &port in &self.wanted_ports {
            let have = self.listeners.iter().filter(|(_, p)| *p == port).count();
            for _ in have..LISTEN_BACKLOG {
                let mut sock = tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
                    tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
                );
                // Listen on any local address (the stack owns STACK_IP and STACK_IP6).
                if sock.listen(port).is_ok() {
                    let h = self.sockets.add(sock);
                    self.listeners.push((h, port));
                }
            }
        }
    }

    /// Promote any listener that has accepted a connection into a [`NetConn`], and
    /// hand the proxy side a `SmoltcpStream`.
    fn promote_listeners(&mut self) {
        let mut i = 0;
        while i < self.listeners.len() {
            let (h, port) = self.listeners[i];
            let state = self.sockets.get_mut::<tcp::Socket>(h).state();
            if state == tcp::State::Listen {
                i += 1;
                continue;
            }
            self.listeners.remove(i);
            if state == tcp::State::Closed {
                self.sockets.remove(h);
                continue;
            }

            let (stream, channel) = stream::channel(self.wake.clone());
            self.conns.insert(h, NetConn::new(channel));
            // Unbounded send never blocks; if the proxy is gone the conn will close.
            let _ = self.new_conn_tx.send(NewConn { stream, port });
        }
    }

    /// Move bytes both ways between smoltcp sockets and their proxy channels, and
    /// reap closed connections.
    fn service_conns(&mut self) {
        let handles: Vec<SocketHandle> = self.conns.keys().copied().collect();
        for h in handles {
            let sock = self.sockets.get_mut::<tcp::Socket>(h);
            let Some(conn) = self.conns.get_mut(&h) else {
                continue; // reaped on a prior iteration
            };

            // `may_send()` becomes true on establishment (and stays true through
            // CloseWait), so this latches once the handshake has completed.
            conn.established |= sock.may_send();

            // proxy → stack (flush any stashed remainder first).
            if let Some(buf) = conn.pending_out.take() {
                push_out(sock, conn, buf);
            }
            while conn.pending_out.is_none() {
                match conn.from_app.try_recv() {
                    Ok(buf) => push_out(sock, conn, buf),
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        conn.app_write_closed = true;
                        break;
                    }
                }
            }
            if conn.app_write_closed && conn.pending_out.is_none() && !conn.sent_fin {
                sock.close();
                conn.sent_fin = true;
            }

            // stack → proxy.
            let mut proxy_gone = false;
            while sock.can_recv() {
                if conn.to_app.is_none() {
                    break;
                }
                // Reserve without holding the borrow across a mutation of `to_app`.
                match conn.to_app.as_ref().unwrap().try_reserve() {
                    Ok(permit) => {
                        let mut chunk = Vec::new();
                        let res = sock.recv(|data| {
                            let n = data.len().min(CHUNK);
                            chunk.extend_from_slice(&data[..n]);
                            (n, ())
                        });
                        if res.is_err() || chunk.is_empty() {
                            break;
                        }
                        permit.send(chunk);
                    }
                    Err(mpsc::error::TrySendError::Full(())) => break,
                    Err(mpsc::error::TrySendError::Closed(())) => {
                        proxy_gone = true;
                        break;
                    }
                }
            }
            if proxy_gone {
                // Proxy dropped the reader: abort the connection.
                sock.abort();
                conn.to_app = None;
            }

            // Peer (child) closed its sending half → surface EOF to the proxy. Only
            // once established, so SynReceived's `!may_recv()` isn't mistaken for EOF.
            if conn.established && !sock.may_recv() {
                conn.to_app = None;
            }

            if sock.state() == tcp::State::Closed {
                self.conns.remove(&h);
                self.sockets.remove(h);
            }
        }
    }
}

/// Push `buf` into a socket's tx buffer, stashing any unwritten remainder.
fn push_out(sock: &mut tcp::Socket, conn: &mut NetConn, buf: Vec<u8>) {
    if !sock.can_send() {
        conn.pending_out = Some(buf);
        return;
    }
    match sock.send_slice(&buf) {
        Ok(n) if n < buf.len() => conn.pending_out = Some(buf[n..].to_vec()),
        Ok(_) => {}
        Err(_) => conn.pending_out = Some(buf),
    }
}

/// Newtype so `AsyncFd` can watch the TUN fd for readability without owning it
/// (the fd is closed when the process exits, not here).
struct TunFd(RawFd);
impl AsRawFd for TunFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}
