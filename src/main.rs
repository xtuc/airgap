//! airgap: run a target program inside its own mount namespace, with sensitive
//! files transparently replaced by FUSE-backed, redacted versions that only that
//! program (and its children) sees.
//!
//! See docs/design.md for the full design. The working directory and the user's
//! home directory are each mounted through a FUSE overlay, so interception is
//! dynamic: any file named `.env` (and any private key, by content) is redacted
//! on access, including files created after launch.

mod fs;
mod profiles;
mod redact;

use std::ffi::OsString;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use fuser::{Config, MountOption};
use nix::errno::Errno;
use nix::fcntl::{open, OFlag};
use nix::mount::{mount, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::stat::Mode;
use nix::unistd::{getgid, getuid};

use crate::fs::OverlayFs;
use crate::profiles::Profile;

/// airgap's command line. The leading flags configure airgap; `program` and
/// everything after it is the wrapped command, passed through verbatim — so
/// `airgap claude --help` runs `claude --help` (the `--help` is the child's).
#[derive(Parser)]
#[command(
    version,
    about = "Run a program with secrets redacted, and (for package managers) file access gated"
)]
struct Cli {
    /// Run a program airgap doesn't recognize, with redaction only and no gate.
    #[arg(long)]
    allow_unknown_program: bool,

    /// Force a profile regardless of the program: `agent` or `npm`.
    #[arg(long, value_name = "NAME")]
    profile: Option<String>,

    /// Log each file access the gate pre-allows (allowlist hits) to stderr.
    #[arg(long)]
    debug: bool,

    /// The program to run, followed by its arguments.
    //
    // One trailing list (rather than a separate program + args positional) so
    // `trailing_var_arg` stops option parsing at the program: everything after it
    // is the child's, verbatim, including flags (`airgap claude --help` runs
    // `claude --help`). A mistyped airgap flag *before* the program is still
    // rejected, and `airgap -- --weird` allows a program whose name starts `-`.
    #[arg(
        trailing_var_arg = true,
        required = true,
        value_name = "PROGRAM [ARGS...]"
    )]
    command: Vec<OsString>,
}

fn main() {
    let cli = Cli::parse();
    // `required = true` guarantees at least the program is present.
    let (program, program_args) = cli
        .command
        .split_first()
        .expect("clap requires a program");

    // Select the program's profile (which also serves as the allowlist) *before*
    // any privileged setup, so a refusal is fast and works without CAP_SYS_ADMIN.
    // An explicit `--profile` overrides name-based resolution (and the allowlist).
    let profile = if let Some(name) = &cli.profile {
        match profiles::by_name(name) {
            Some(p) => p,
            None => {
                eprintln!(
                    "airgap: unknown profile '{name}' (expected one of: {})",
                    profiles::names().join(", ")
                );
                std::process::exit(2);
            }
        }
    } else {
        match profiles::resolve(program) {
            Some(p) => p,
            None if cli.allow_unknown_program => profiles::unrestricted(),
            None => {
                let name = profiles::program_basename(program).to_string_lossy();
                eprintln!(
                    "airgap: refusing to run '{name}': not a recognized program ({}).\n  \
                     airgap applies a per-program profile; to run something without one, \
                     pass --allow-unknown-program:\n\n      \
                     airgap --allow-unknown-program {name} [args...]",
                    profiles::permitted_programs().join(", ")
                );
                std::process::exit(1);
            }
        }
    };

    match run(program, program_args, profile.as_ref(), cli.debug) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("airgap: {e:#}");
            std::process::exit(1);
        }
    }
}

/// Set up the namespace and FUSE overlays, run the child, tear down, and return
/// the child's exit code. The `profile` decides redaction and whether a directory
/// gate is attached (one shared instance consulted by every overlay). `debug`
/// makes the gate log the accesses it pre-allows.
fn run(
    program: &OsString,
    program_args: &[OsString],
    profile: &dyn Profile,
    debug: bool,
) -> Result<i32> {
    // Enter a fresh mount namespace, then make the tree private so our overlay
    // doesn't propagate back to the host's namespace. We get the namespace from
    // an unprivileged user namespace (no sudo/setcap), falling back to a plain
    // mount namespace if the kernel forbids that.
    enter_namespaces()?;
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
    if debug {
        eprintln!(
            "airgap[debug]: overlay targets (redaction {}): {}",
            if profile.redaction() { "on" } else { "off" },
            targets
                .iter()
                .map(|t| t.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // Translate the declarative profile into runtime policy: redaction, and a
    // single directory gate shared across all overlays (so a directory is
    // decided once regardless of which overlay serves it).
    let redact = profile.redaction();
    let gate = profile.directory_gate(program, debug);

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
        let overlay = OverlayFs::new(root, dir.clone(), redact, gate.clone());
        let session = fuser::spawn_mount2(overlay, dir, &config)
            .with_context(|| format!("mounting overlay at {}", dir.display()))?;
        if debug {
            eprintln!("airgap[debug]: mounted FUSE overlay at {}", dir.display());
        }
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
    if let Some(home) = std::env::var_os("HOME").filter(|h| !h.is_empty())
        && let Ok(home) = std::fs::canonicalize(&home)
    {
        candidates.push(home);
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

/// Acquire a private mount namespace without host privilege.
///
/// The preferred path is an unprivileged *user* namespace: inside it the process
/// holds a full capability set (including `CAP_SYS_ADMIN`), which is enough to
/// create the mount namespace, make the tree private, and mount the FUSE overlay
/// — no `sudo` and no `setcap`. The combined `unshare` also creates the new mount
/// namespace, owned by the user namespace.
///
/// If the kernel forbids unprivileged user namespaces (e.g. Ubuntu's AppArmor
/// restriction, or `kernel.unprivileged_userns_clone=0`), we fall back to a plain
/// mount namespace, which still works if the binary was granted `CAP_SYS_ADMIN`
/// via `setcap`. Only if both fail do we surface an actionable message.
fn enter_namespaces() -> Result<()> {
    // Capture the real ids *before* unsharing: once inside the new user
    // namespace, and before its maps are written, getuid/getgid report the
    // overflow id (nobody, 65534), which would produce a bogus, rejected map.
    let uid = getuid().as_raw();
    let gid = getgid().as_raw();
    match unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS) {
        Ok(()) => map_ids_to_self(uid, gid).context("configuring user namespace id maps"),
        // Unprivileged user namespaces are disabled; try a plain mount namespace.
        Err(Errno::EPERM) => unshare(CloneFlags::CLONE_NEWNS).map_err(|e| match e {
            Errno::EPERM => anyhow!(missing_privilege_msg()),
            other => anyhow!("unshare(CLONE_NEWNS) failed: {other}"),
        }),
        Err(other) => Err(anyhow!("unshare(CLONE_NEWUSER|CLONE_NEWNS) failed: {other}")),
    }
}

/// Identity-map our own uid and gid into the new user namespace, so the child
/// keeps its real uid/gid (transparency) and accesses to the real files behind
/// the overlay still resolve as the real user. `setgroups` must be denied before
/// the `gid_map` write, or an unprivileged write returns EPERM.
fn map_ids_to_self(uid: u32, gid: u32) -> Result<()> {
    std::fs::write("/proc/self/setgroups", "deny").context("/proc/self/setgroups")?;
    std::fs::write("/proc/self/uid_map", format!("{uid} {uid} 1")).context("/proc/self/uid_map")?;
    std::fs::write("/proc/self/gid_map", format!("{gid} {gid} 1")).context("/proc/self/gid_map")?;
    Ok(())
}

/// Actionable message for when we can get a mount namespace neither from an
/// unprivileged user namespace nor from `CAP_SYS_ADMIN` on the binary.
fn missing_privilege_msg() -> String {
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "airgap".to_string());
    format!(
        "could not create a mount namespace: unprivileged user namespaces appear \
         to be disabled, and the binary lacks CAP_SYS_ADMIN.\n\n  \
         Either enable unprivileged user namespaces (pick what applies):\n\n      \
         sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0   # Ubuntu 24.04+\n      \
         sudo sysctl -w kernel.unprivileged_userns_clone=1               # some Debian/Ubuntu\n\n  \
         or grant the capability to the binary once:\n\n      \
         sudo setcap cap_sys_admin+ep {exe}\n\n  \
         (the capability is lost on rebuild/copy, so re-run it after each \
         `cargo build` or `cargo install`)."
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

    // --- argument parsing (clap) -------------------------------------------

    /// Parse as if from `argv` (clap expects argv[0] to be the binary name).
    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("airgap").chain(args.iter().copied()))
    }

    fn osvec(items: &[&str]) -> Vec<OsString> {
        items.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_program_and_args() {
        let cli = parse(&["claude", "--model", "opus"]).unwrap();
        assert!(!cli.allow_unknown_program);
        assert_eq!(cli.command, osvec(&["claude", "--model", "opus"]));
    }

    #[test]
    fn parses_allow_unknown_flag() {
        let cli = parse(&["--allow-unknown-program", "cat", ".env"]).unwrap();
        assert!(cli.allow_unknown_program);
        assert_eq!(cli.command, osvec(&["cat", ".env"]));
    }

    #[test]
    fn parses_profile_override() {
        let cli = parse(&["--profile", "npm", "cat", "x"]).unwrap();
        assert_eq!(cli.profile.as_deref(), Some("npm"));
        assert_eq!(cli.command, osvec(&["cat", "x"]));
    }

    #[test]
    fn profile_without_value_is_an_error() {
        assert!(parse(&["--profile"]).is_err());
    }

    #[test]
    fn parses_debug_flag() {
        let cli = parse(&["--debug", "npm", "install"]).unwrap();
        assert!(cli.debug);
        assert_eq!(cli.command, osvec(&["npm", "install"]));
        // Off by default.
        assert!(!parse(&["npm"]).unwrap().debug);
    }

    #[test]
    fn flags_after_program_belong_to_the_child() {
        // `--allow-unknown-program` after the program is the child's arg, not ours.
        let cli = parse(&["claude", "--allow-unknown-program"]).unwrap();
        assert!(!cli.allow_unknown_program);
        assert_eq!(cli.command, osvec(&["claude", "--allow-unknown-program"]));
    }

    #[test]
    fn double_dash_ends_flag_parsing() {
        // `--` lets a program whose name starts with `-` be specified.
        let cli = parse(&["--", "--weird-name", "arg"]).unwrap();
        assert!(!cli.allow_unknown_program);
        assert_eq!(cli.command, osvec(&["--weird-name", "arg"]));
    }

    #[test]
    fn missing_program_is_a_usage_error() {
        assert!(parse(&[]).is_err());
        assert!(parse(&["--allow-unknown-program"]).is_err());
        assert!(parse(&["--"]).is_err());
    }

    #[test]
    fn unknown_flag_is_rejected() {
        assert!(parse(&["--nope", "claude"]).is_err());
    }
}
