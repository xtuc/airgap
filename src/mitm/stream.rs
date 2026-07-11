//! The async byte-stream bridge between the netstack loop and the proxy.
//!
//! Each accepted stack connection is a pair: the proxy gets a [`SmoltcpStream`]
//! (an `AsyncRead`/`AsyncWrite`), and the stack keeps the other end of the two
//! channels via [`StackChannel`]. [`channel`] builds both halves at once.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc};
use tokio_util::sync::PollSender;

/// Per-direction channel depth between the stack and the proxy.
const CHAN_CAP: usize = 16;

/// A new TCP connection accepted by the stack, handed to the proxy.
pub(super) struct NewConn {
    pub(super) stream: SmoltcpStream,
    /// Local port it connected to (443 → TLS, else rejected).
    pub(super) port: u16,
}

/// The stack-facing endpoints of a connection, paired with the [`SmoltcpStream`]
/// the proxy holds. Owned by the netstack loop's per-connection bookkeeping.
pub(super) struct StackChannel {
    /// Stack → proxy.
    pub(super) to_app: mpsc::Sender<Vec<u8>>,
    /// Proxy → stack.
    pub(super) from_app: mpsc::Receiver<Vec<u8>>,
}

/// Build a connected pair: the proxy-facing [`SmoltcpStream`] and the stack-facing
/// [`StackChannel`]. `wake` is notified whenever the proxy writes / shuts down, so
/// the stack loop reacts without busy-waiting.
pub(super) fn channel(wake: Arc<Notify>) -> (SmoltcpStream, StackChannel) {
    let (to_app_tx, to_app_rx) = mpsc::channel::<Vec<u8>>(CHAN_CAP);
    let (from_app_tx, from_app_rx) = mpsc::channel::<Vec<u8>>(CHAN_CAP);
    let stream = SmoltcpStream {
        from_net: to_app_rx,
        to_net: Some(PollSender::new(from_app_tx)),
        wake,
        read_rem: None,
    };
    let channel = StackChannel {
        to_app: to_app_tx,
        from_app: from_app_rx,
    };
    (stream, channel)
}

/// The proxy-facing end of a connection: an `AsyncRead`/`AsyncWrite` backed by
/// the channels the netstack loop services.
pub(super) struct SmoltcpStream {
    /// Stack → proxy.
    from_net: mpsc::Receiver<Vec<u8>>,
    /// Proxy → stack; `None` after shutdown.
    to_net: Option<PollSender<Vec<u8>>>,
    /// Wake the stack loop when we hand it data / shut down.
    wake: Arc<Notify>,
    /// Leftover of a chunk not fully copied into the last read buffer.
    read_rem: Option<(Vec<u8>, usize)>,
}

impl AsyncRead for SmoltcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = &mut *self;
        loop {
            if let Some((data, off)) = me.read_rem.as_mut() {
                let n = buf.remaining().min(data.len() - *off);
                buf.put_slice(&data[*off..*off + n]);
                *off += n;
                if *off >= data.len() {
                    me.read_rem = None;
                }
                return Poll::Ready(Ok(()));
            }
            match me.from_net.poll_recv(cx) {
                Poll::Ready(Some(v)) if v.is_empty() => continue,
                Poll::Ready(Some(v)) => me.read_rem = Some((v, 0)),
                Poll::Ready(None) => return Poll::Ready(Ok(())), // EOF
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for SmoltcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = &mut *self;
        let Some(sender) = me.to_net.as_mut() else {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        };
        match sender.poll_reserve(cx) {
            Poll::Ready(Ok(())) => {
                let _ = sender.send_item(data.to_vec());
                me.wake.notify_one();
                Poll::Ready(Ok(data.len()))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        // Drop the sender → the stack sees the channel disconnect and FINs.
        self.to_net = None;
        self.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}
