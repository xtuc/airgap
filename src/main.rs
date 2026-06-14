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
use std::path::{Path, PathBuf};
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

    // The directories to protect: the working directory and the user's home.
    // If one nests inside the other (typically cwd inside `$HOME`), only the
    // outermost is kept — its overlay already redacts everything beneath it.
    let cwd = std::env::current_dir().context("getting current dir")?;
    let targets = overlay_targets(&cwd);

    let mut config = Config::default();
    config.mount_options = vec![MountOption::FSName("airgap".into())];

    // Mount a FUSE overlay over each target. Each backend first captures an
    // `O_PATH` fd to the *real* directory, before its overlay is mounted, so it
    // reaches the real files (via `*at`) without recursing through FUSE; targets
    // never nest, so one overlay's mount can't shadow another's fd. O_CLOEXEC so
    // the child can't inherit the fds. Every file the child accesses under a
    // target now flows through its overlay.
    let mut sessions = Vec::new();
    for dir in &targets {
        let root = open(
            dir,
            OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .with_context(|| format!("opening {}", dir.display()))?;
        let session = fuser::spawn_mount2(OverlayFs::new(root), dir, &config)
            .with_context(|| format!("mounting overlay at {}", dir.display()))?;
        sessions.push(session);
    }

    // Our cwd was opened before the mounts, so it still points at the
    // *underlying* directory; re-enter the path so it (and the child that
    // inherits it) resolves through the overlay. Otherwise relative accesses
    // would bypass redaction.
    std::env::set_current_dir(&cwd)
        .with_context(|| format!("re-entering working directory {}", cwd.display()))?;

    // Run the child (inherits our namespace and cwd, so it sees the overlays),
    // then unmount regardless of how it went.
    let result = spawn_and_wait(program, program_args);
    drop(sessions); // unmounts every overlay
    result
}

/// The directories to overlay: the working directory and the user's home
/// (`$HOME`). Home is resolved through symlinks and dropped if `$HOME` is unset,
/// empty, or doesn't resolve. The result is de-duplicated by [`dedup_targets`] so
/// nested directories collapse to their outermost ancestor.
fn overlay_targets(cwd: &Path) -> Vec<PathBuf> {
    let mut candidates = vec![cwd.to_path_buf()];
    if let Some(home) = std::env::var_os("HOME") {
        if !home.is_empty() {
            if let Ok(home) = std::fs::canonicalize(&home) {
                candidates.push(home);
            }
        }
    }
    dedup_targets(candidates)
}

/// Reduce a list of directories to the minimal set whose overlays cover them
/// all: drop any directory equal to or nested within another, keeping only the
/// outermost ancestors. Order of the survivors follows first appearance.
fn dedup_targets(candidates: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut targets: Vec<PathBuf> = Vec::new();
    for dir in candidates {
        // Already covered by a kept ancestor (or an exact duplicate)?
        if targets.iter().any(|kept| dir.starts_with(kept)) {
            continue;
        }
        // This dir supersedes any kept dirs nested within it.
        targets.retain(|kept| !kept.starts_with(&dir));
        targets.push(dir);
    }
    targets
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

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(items: &[&str]) -> Vec<PathBuf> {
        items.iter().map(PathBuf::from).collect()
    }

    #[test]
    fn keeps_disjoint_dirs() {
        assert_eq!(
            dedup_targets(paths(&["/tmp/work", "/home/sven"])),
            paths(&["/tmp/work", "/home/sven"])
        );
    }

    #[test]
    fn drops_cwd_nested_in_home() {
        // cwd inside $HOME: only $HOME survives, covering the cwd beneath it.
        assert_eq!(
            dedup_targets(paths(&["/home/sven/proj", "/home/sven"])),
            paths(&["/home/sven"])
        );
    }

    #[test]
    fn drops_home_nested_in_cwd() {
        // The outermost wins regardless of order.
        assert_eq!(
            dedup_targets(paths(&["/", "/home/sven"])),
            paths(&["/"])
        );
    }

    #[test]
    fn collapses_exact_duplicate() {
        // cwd == $HOME: a single overlay.
        assert_eq!(
            dedup_targets(paths(&["/home/sven", "/home/sven"])),
            paths(&["/home/sven"])
        );
    }

    #[test]
    fn sibling_prefix_is_not_nesting() {
        // `/home/sven2` is not under `/home/sven` despite the string prefix;
        // path-component matching keeps them distinct.
        assert_eq!(
            dedup_targets(paths(&["/home/sven", "/home/sven2"])),
            paths(&["/home/sven", "/home/sven2"])
        );
    }
}
