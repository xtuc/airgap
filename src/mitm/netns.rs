//! Network-namespace entry and in-process interface configuration.
//!
//! The netns unshare is per-thread (`CLONE_NEWNET`), so only the netstack thread
//! (and the child that joins it via `setns`) leaves the init netns; airgap's other
//! threads keep real egress. The interface is configured over rtnetlink, in
//! process — no shelling out to `ip`.

use std::net::IpAddr;
use std::os::fd::OwnedFd;

use anyhow::{Context, Result, anyhow};
use nix::fcntl::OFlag;
use nix::sched::{CloneFlags, unshare};
use nix::sys::stat::Mode;

use super::{CHILD_IP, CHILD_IP6, PREFIX_LEN, PREFIX_LEN6, TUN_NAME};

/// Enter a fresh network namespace on the *calling thread*. Per-thread, so it does
/// not have the single-threaded restriction that `CLONE_NEWUSER` does.
pub(super) fn enter_new_netns() -> Result<()> {
    unshare(CloneFlags::CLONE_NEWNET).map_err(|e| anyhow!("unshare(CLONE_NEWNET): {e}"))
}

/// Open the *calling thread's* network namespace (the one it just unshared), for
/// the child to join via `setns`.
pub(super) fn open_thread_netns() -> Result<OwnedFd> {
    nix::fcntl::open(
        "/proc/thread-self/ns/net",
        OFlag::O_RDONLY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .context("opening /proc/thread-self/ns/net")
}

/// Configure the TUN in-process via rtnetlink: bring it (and `lo`) up, assign
/// `CHILD_IP/PREFIX_LEN`, and add a default route out the TUN.
pub(super) async fn configure_interface() -> Result<()> {
    let (conn, handle, _) = rtnetlink::new_connection().context("opening rtnetlink connection")?;
    tokio::spawn(conn);

    let idx = nix::net::if_::if_nametoindex(TUN_NAME)
        .with_context(|| format!("resolving ifindex of {TUN_NAME}"))?;

    // Loopback up is best-effort (some clients expect it).
    if let Ok(lo) = nix::net::if_::if_nametoindex("lo") {
        let _ = handle.link().set(lo).up().execute().await;
    }

    handle
        .link()
        .set(idx)
        .up()
        .execute()
        .await
        .with_context(|| format!("bringing {TUN_NAME} up"))?;
    handle
        .address()
        .add(idx, IpAddr::V4(CHILD_IP), PREFIX_LEN)
        .execute()
        .await
        .with_context(|| format!("assigning {CHILD_IP}/{PREFIX_LEN} to {TUN_NAME}"))?;

    // Disable IPv6 Duplicate Address Detection on the TUN so the address is usable
    // immediately: in an isolated netns nothing can collide, and DAD would
    // otherwise leave the address "tentative" for a moment. Best-effort.
    let _ = std::fs::write(
        format!("/proc/sys/net/ipv6/conf/{TUN_NAME}/accept_dad"),
        b"0",
    );
    handle
        .address()
        .add(idx, IpAddr::V6(CHILD_IP6), PREFIX_LEN6)
        .execute()
        .await
        .with_context(|| format!("assigning {CHILD_IP6}/{PREFIX_LEN6} to {TUN_NAME}"))?;

    // Default routes out the TUN so literal-IP egress is captured too (and then
    // dropped by the stack, which only owns its own addresses). Best-effort: the
    // connected /24 + /64 already cover the happy path (DNS + the stack's IPs).
    if let Err(e) = handle
        .route()
        .add()
        .v4()
        .destination_prefix(std::net::Ipv4Addr::UNSPECIFIED, 0)
        .output_interface(idx)
        .execute()
        .await
    {
        log::debug!("mitm: v4 default route add failed (non-fatal): {e}");
    }
    if let Err(e) = handle
        .route()
        .add()
        .v6()
        .destination_prefix(std::net::Ipv6Addr::UNSPECIFIED, 0)
        .output_interface(idx)
        .execute()
        .await
    {
        log::debug!("mitm: v6 default route add failed (non-fatal): {e}");
    }
    Ok(())
}
