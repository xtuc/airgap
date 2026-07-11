//! The TUN device: creation, the smoltcp phy [`Device`] impl, and packet
//! draining off the fd.

use std::collections::{BTreeSet, VecDeque};
use std::io;
use std::os::fd::RawFd;

use anyhow::{Result, anyhow, bail};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant as SmolInstant;

/// TUN MTU.
const MTU: usize = 1500;
/// `TUNSETIFF` ioctl (`_IOW('T', 202, int)`); not exposed by the `libc` crate.
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

/// A TUN interface: owns its fd, buffers inbound packets, and is the smoltcp
/// [`Device`] the stack polls. The fd is non-blocking + close-on-exec and is
/// released when the process exits (not on drop).
pub(super) struct Tun {
    fd: RawFd,
    /// Packets already read off the TUN by [`Tun::drain`], waiting for smoltcp to
    /// consume them. Reading happens *before* the poll so we can create a listener
    /// for a new destination port before smoltcp processes its SYN (an unmatched
    /// SYN would otherwise be RST'd → the client sees "connection refused").
    inbox: VecDeque<Vec<u8>>,
}

impl Tun {
    /// Open `/dev/net/tun`, attach a TUN interface named `name`, and return the
    /// [`Tun`] (non-blocking, close-on-exec).
    pub(super) fn create(name: &str) -> Result<Tun> {
        #[repr(C)]
        struct IfReq {
            name: [libc::c_char; 16],
            flags: libc::c_short,
            _pad: [u8; 22],
        }

        // SAFETY: constant, NUL-terminated path.
        let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(anyhow!("open /dev/net/tun: {}", io::Error::last_os_error()));
        }

        let nb = name.as_bytes();
        if nb.len() >= 16 {
            bail!("TUN name too long: {name}");
        }
        // SAFETY: zeroed ifreq, then set name + flags.
        let mut req: IfReq = unsafe { std::mem::zeroed() };
        for (i, b) in nb.iter().enumerate() {
            req.name[i] = *b as libc::c_char;
        }
        req.flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
        // SAFETY: valid fd + ifreq pointer.
        let r = unsafe { libc::ioctl(fd, TUNSETIFF, &mut req as *mut IfReq) };
        if r < 0 {
            let e = io::Error::last_os_error();
            // SAFETY: closing the fd we just opened.
            unsafe { libc::close(fd) };
            return Err(anyhow!("TUNSETIFF({name}): {e}"));
        }

        // Non-blocking, so smoltcp's device reads return instead of stalling.
        // SAFETY: valid fd.
        let ok = unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            flags >= 0 && libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) >= 0
        };
        if !ok {
            let e = io::Error::last_os_error();
            // SAFETY: closing the fd we just opened.
            unsafe { libc::close(fd) };
            return Err(anyhow!("setting O_NONBLOCK on {name}: {e}"));
        }
        Ok(Tun {
            fd,
            inbox: VecDeque::new(),
        })
    }

    /// The raw fd, for registering with the reactor (see [`super::stack`]).
    pub(super) fn as_raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Read every packet currently pending on the TUN into the inbox, recording
    /// the destination port of each new TCP SYN in `wanted` so a listener can be
    /// created before smoltcp processes it. Stops at `EWOULDBLOCK` (non-blocking).
    pub(super) fn drain(&mut self, wanted: &mut BTreeSet<u16>) {
        loop {
            let mut buf = vec![0u8; MTU];
            // SAFETY: valid non-blocking fd, buffer of len MTU.
            let n =
                unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n > 0 {
                buf.truncate(n as usize);
                if let Some(port) = syn_dest_port(&buf) {
                    wanted.insert(port);
                }
                self.inbox.push_back(buf);
                continue;
            }
            if n == 0 {
                break; // TUN has no more queued packets
            }
            // n < 0: distinguish "drained" from a transient/real error.
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                // EAGAIN == EWOULDBLOCK on Linux: nothing left to read.
                Some(libc::EAGAIN) => break,
                Some(libc::EINTR) => continue, // interrupted; retry
                _ => {
                    log::warn!("mitm: TUN read error: {e}");
                    break;
                }
            }
        }
    }
}

impl Device for Tun {
    type RxToken<'a> = TunRxToken;
    type TxToken<'a> = TunTxToken;

    fn receive(&mut self, _t: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buf = self.inbox.pop_front()?;
        Some((TunRxToken(buf), TunTxToken { fd: self.fd }))
    }

    fn transmit(&mut self, _t: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TunTxToken { fd: self.fd })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
        caps
    }
}

pub(super) struct TunRxToken(Vec<u8>);

impl RxToken for TunRxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

pub(super) struct TunTxToken {
    fd: RawFd,
}

impl TxToken for TunTxToken {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        // SAFETY: valid fd, buffer of len bytes.
        let n = unsafe { libc::write(self.fd, buf.as_ptr() as *const libc::c_void, len) };
        // smoltcp's TxToken can't report failure back to the stack; a dropped or
        // short write just means that packet is lost and will be retransmitted, so
        // log it rather than panicking.
        if n < 0 {
            log::debug!("mitm: TUN write failed: {}", io::Error::last_os_error());
        } else if (n as usize) < len {
            log::debug!("mitm: short TUN write ({n}/{len} bytes)");
        }
        r
    }
}

/// The destination port of a TCP SYN (not SYN-ACK), or `None` for any other
/// packet. Handles IPv4 and IPv6 (with no extension headers, as a fresh SYN
/// normally has none). Used to spin up a listener for a port the child dials on
/// the fly.
fn syn_dest_port(pkt: &[u8]) -> Option<u16> {
    const IPPROTO_TCP: u8 = 6;
    let tcp = match pkt.first()? >> 4 {
        4 => {
            if pkt.len() < 20 || pkt[9] != IPPROTO_TCP {
                return None; // not IPv4/TCP
            }
            let ihl = (pkt[0] & 0x0f) as usize * 4;
            pkt.get(ihl..)?
        }
        6 => {
            // Fixed 40-byte IPv6 header; next-header (byte 6) must be TCP.
            if pkt.len() < 40 || pkt[6] != IPPROTO_TCP {
                return None; // not IPv6/TCP (or carries extension headers)
            }
            pkt.get(40..)?
        }
        _ => return None,
    };
    if tcp.len() < 20 {
        return None;
    }
    let flags = tcp[13];
    let (syn, ack) = (flags & 0x02 != 0, flags & 0x10 != 0);
    (syn && !ack).then(|| u16::from_be_bytes([tcp[2], tcp[3]]))
}
