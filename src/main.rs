//! airgap: run a target program inside its own mount namespace, with sensitive
//! files transparently replaced by FUSE-backed, redacted versions that only that
//! program (and its children) sees.
//!
//! See docs/design.md for the full design. The working directory and the user's
//! home directory are each mounted through a FUSE overlay, so interception is
//! dynamic: any file named `.env` (and any private key, by content) is redacted
//! on access, including files created after launch.

mod fs;
mod handlers;

use std::ffi::OsString;
use std::os::unix::process::ExitStatusExt;
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use fuser::{Config, MountOption};
use nix::errno::Errno;
use nix::fcntl::{open, OFlag};
use nix::mount::{mount, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::stat::Mode;

use crate::fs::OverlayFs;

fn main() {
    // argv[0] is our own name; the rest is `<program> [args...]`.
    let mut args = std::env::args_os();
    let _self = args.next();
    let program = match args.next() {
        Some(p) => p,
        None => {
            eprintln!("usage: airgap <program> [args...]");
            std::process::exit(2);
        }
    };
    let program_args: Vec<OsString> = args.collect();

    match run(&program, &program_args) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("airgap: {e:#}");
            std::process::exit(1);
        }
    }
}

/// Set up the namespace and FUSE overlay, run the child, tear down, and return
/// the child's exit code.
fn run(program: &OsString, program_args: &[OsString]) -> Result<i32> {
    // New mount namespace, then make the tree private so our overlay doesn't
    // propagate back to the host's namespace. EPERM here means we lack
    // CAP_SYS_ADMIN, so turn it into an actionable message.
    unshare(CloneFlags::CLONE_NEWNS).map_err(|e| match e {
        Errno::EPERM => anyhow!(missing_cap_sys_admin_msg()),
        other => anyhow!("unshare(CLONE_NEWNS) failed: {other}"),
    })?;
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .context("making mounts private")?;

    // Capture a dir fd to the *real* working directory before mounting the
    // overlay over it, so the backend reaches the real files (via `*at`)
    // without recursing through FUSE. O_CLOEXEC so the child can't inherit it.
    let cwd = std::env::current_dir().context("getting current dir")?;
    let root = open(
        &cwd,
        OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("opening working directory {}", cwd.display()))?;

    // Mount the FUSE overlay over the working directory, on a background
    // thread. Every file the child accesses now flows through it.
    let mut config = Config::default();
    config.mount_options = vec![MountOption::FSName("airgap".into())];
    let session = fuser::spawn_mount2(OverlayFs::new(root), &cwd, &config)
        .with_context(|| format!("mounting overlay at {}", cwd.display()))?;

    // Our cwd was opened before the mount, so it still points at the *underlying*
    // directory; re-enter the path so it (and the child that inherits it) resolves
    // through the overlay. Otherwise relative accesses would bypass redaction.
    std::env::set_current_dir(&cwd)
        .with_context(|| format!("re-entering working directory {}", cwd.display()))?;

    // Run the child (inherits our namespace and cwd, so it sees the overlay),
    // then unmount regardless of how it went.
    let result = spawn_and_wait(program, program_args);
    drop(session); // unmounts the overlay at `cwd`
    result
}

/// Actionable message for the EPERM that `unshare`/`mount` return when the
/// binary lacks CAP_SYS_ADMIN, pointing at the one-time `setcap` fix.
fn missing_cap_sys_admin_msg() -> String {
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "airgap".to_string());
    format!(
        "missing CAP_SYS_ADMIN, required to create a mount namespace and mount \
         the FUSE overlay.\n  Grant it to the binary once with:\n\n      sudo \
         setcap cap_sys_admin+ep {exe}\n\n  \
         (the capability is lost on rebuild/copy, so re-run it after each \
         `cargo build` or `cargo install`), or run airgap inside an unprivileged user namespace."
    )
}

/// Spawn the child, wait for it, and return its exit code (signal → 128 + signo).
fn spawn_and_wait(program: &OsString, program_args: &[OsString]) -> Result<i32> {
    let status = Command::new(program)
        .args(program_args)
        .status()
        .with_context(|| format!("running {program:?}"))?;
    Ok(match status.code() {
        Some(code) => code,
        None => 128 + status.signal().unwrap_or(0),
    })
}
