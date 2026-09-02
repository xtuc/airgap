//! airgap: run a target program inside its own mount namespace, with sensitive
//! files transparently replaced by FUSE-backed, redacted versions that only that
//! program (and its children) sees.
//!
//! See docs/design.md for the full design. The working directory and the user's
//! home directory are each mounted through a FUSE overlay, so interception is
//! dynamic: any file named `.env` (and any private key, by content) is redacted
//! on access, including files created after launch.

mod fs;
mod logging;
mod mitm;
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

    /// Enable debug-level logging (e.g. each file access the gate pre-allows).
    #[arg(long)]
    debug: bool,

    /// Write airgap's own logs to PATH instead of the default
    /// ($XDG_STATE_HOME/airgap/airgap.log, else ~/.local/state/airgap/airgap.log).
    #[arg(long, value_name = "PATH")]
    log_file: Option<PathBuf>,

    /// Enable the experimental network interception (MitM): transparently
    /// intercept the child's HTTPS traffic and rewrite request headers per the
    /// config.
    #[arg(long)]
    mitm: bool,

    /// Path to the MitM header-rewrite config (YAML).
    #[arg(
        long,
        value_name = "PATH",
        requires = "mitm",
        required_if_eq("mitm", "true")
    )]
    mitm_config: Option<PathBuf>,

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

    // Route everything through the centralized logger.
    logging::init(cli.debug, cli.log_file);

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

    // clap ties the two flags together — `--mitm` requires a config path and a
    // config without `--mitm` is rejected — so the config being `Some` is
    // exactly "intercept, using this file", and `--mitm` needs no further check.
    match run(program, program_args, profile.as_ref(), cli.mitm_config) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("airgap: {e:#}");
            std::process::exit(1);
        }
    }
}

/// Set up the namespace and FUSE overlays, run the child, tear down, and return
/// the child's exit code. The `profile` decides redaction and whether a directory
/// gate is attached (one shared instance consulted by every overlay). Verbosity
/// is controlled centrally by the logger (see [`logging`]); `--debug` raises it.
fn run(
    program: &OsString,
    program_args: &[OsString],
    profile: &dyn Profile,
    mitm_config: Option<PathBuf>,
) -> Result<i32> {
    // Build the TLS machinery *before* entering namespaces (it spawns no
    // threads, so the single-threaded `unshare(CLONE_NEWUSER)` below still works;
    // and it reads the config + host trust store against the real filesystem).
    // The netns + user-space stack are started later, once we hold CAP_NET_ADMIN
    // in our user namespace. Only runs when `--mitm` was passed (mitm_config is
    // Some); if setup fails we log and run with FUSE only.
    let mut mitm = match &mitm_config {
        Some(config) => match mitm::setup(config) {
            Ok(m) => Some(m),
            Err(e) => {
                log::warn!("MitM disabled: {e:#}");
                None
            }
        },
        None => None,
    };

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
    log::debug!(
        "overlay targets (redaction {}): {}",
        if profile.redaction() { "on" } else { "off" },
        targets
            .iter()
            .map(|t| t.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    // Translate the declarative profile into runtime policy: redaction, and a
    // single directory gate shared across all overlays (so a directory is
    // decided once regardless of which overlay serves it).
    let redact = profile.redaction();
    let gate = profile.directory_gate(program);

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
        log::debug!("mounted FUSE overlay at {}", dir.display());
        sessions.push(session);
    }

    // Bring up the child's network namespace + user-space stack now: we hold
    // CAP_NET_ADMIN in our user namespace, and this thread has finished the
    // single-threaded `unshare(CLONE_NEWUSER)`, so the per-thread netns unshare
    // inside is safe. The child joins the netns via a `setns` pre_exec hook.
    if let Some(m) = mitm.as_mut() {
        m.start_netstack().context("starting MitM network stack")?;
    }

    // Our cwd was opened before the mounts, so it still points at the
    // *underlying* directory; re-enter the path so it (and the child that
    // inherits it) resolves through the overlay. Otherwise relative accesses
    // would bypass redaction.
    // Expose our ephemeral CA to the child as the on-disk system trust store:
    // bind-mount the augmented bundle (real roots + our CA) over the distro's
    // bundle. This is namespace-local, so the host store is untouched, and it
    // covers any TLS stack that reads the system store (OpenSSL, curl, Go, …)
    // without per-tool env vars. (The child's resolver is pointed at the stack's
    // stub separately, in its own mount namespace via the pre_exec hook, so
    // airgap's proxy keeps the host resolver for upstream DNS.)
    if let Some(m) = &mitm {
        let target = mitm::SYSTEM_CA_BUNDLE;
        if Path::new(target).exists() {
            mount(
                Some(m.ca_bundle_path.as_path()),
                target,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
            .with_context(|| format!("bind-mounting MitM CA bundle over {target}"))?;
            log::debug!("bind-mounted MitM CA bundle over {target}");
        } else {
            log::debug!("{target} absent; relying on CA env vars only");
        }
    }

    std::env::set_current_dir(&cwd)
        .with_context(|| format!("re-entering working directory {}", cwd.display()))?;

    // Start the MitM proxy (in the init netns, so upstream has real egress) that
    // consumes the byte streams the stack accepts.
    if let Some(m) = mitm.as_mut() {
        m.start_proxy().context("starting MitM proxy")?;
    }

    // Run the child (inherits our namespace and cwd, so it sees the overlays),
    // then unmount regardless of how it went.
    let result = spawn_and_wait(program, program_args, mitm.as_ref());
    drop(sessions); // unmounts every overlay
    drop(mitm); // stops the stack/proxy threads (process teardown), removes temp files
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
///
/// When the MitM is active, the child gets our ephemeral CA pointed to by the
/// common TLS-trust env vars, and a `pre_exec` hook that joins the network
/// namespace so (and only so) its traffic is routed through the user-space stack.
fn spawn_and_wait(
    program: &OsString,
    program_args: &[OsString],
    mitm: Option<&mitm::Mitm>,
) -> Result<i32> {
    let mut cmd = Command::new(program);
    cmd.args(program_args);

    if let Some(m) = mitm {
        // The system trust store is already covered by the bind-mount above, but
        // several stacks read an env var *instead of* the system store — and if
        // one is already set in the inherited environment (e.g. SSL_CERT_FILE
        // pointing at a VPN's bundle) it silently wins over our bind-mount. So
        // point them all at our augmented bundle (real roots + our CA), which is
        // a superset and overrides any inherited value:
        //   - SSL_CERT_FILE / CURL_CA_BUNDLE — OpenSSL & curl (and wget, python `ssl`)
        //   - REQUESTS_CA_BUNDLE — Python `requests` (certifi)
        //   - NODE_EXTRA_CA_CERTS — Node (appends our bare CA to its bundled roots)
        cmd.env("SSL_CERT_FILE", &m.ca_bundle_path)
            .env("CURL_CA_BUNDLE", &m.ca_bundle_path)
            .env("REQUESTS_CA_BUNDLE", &m.ca_bundle_path)
            .env("NODE_EXTRA_CA_CERTS", &m.ca_path);

        let hook = m.child_setup_hook()?;
        // SAFETY: the hook is async-signal-safe (setns/unshare/mount on
        // pre-opened fds and pre-built strings; no allocation).
        unsafe {
            std::os::unix::process::CommandExt::pre_exec(&mut cmd, hook);
        }
    }

    let status = cmd
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
    fn parses_log_file_flag() {
        let cli = parse(&["--log-file", "/tmp/x.log", "npm"]).unwrap();
        assert_eq!(cli.log_file.as_deref(), Some(Path::new("/tmp/x.log")));
        // None by default (logging falls back to the XDG default).
        assert!(parse(&["npm"]).unwrap().log_file.is_none());
    }

    #[test]
    fn mitm_and_mitm_config_require_each_other() {
        let cli = parse(&["--mitm", "--mitm-config", "/tmp/m.yaml", "npm"]).unwrap();
        assert!(cli.mitm);
        assert_eq!(cli.mitm_config.as_deref(), Some(Path::new("/tmp/m.yaml")));
        // There is no default location, so neither flag works alone.
        assert!(parse(&["--mitm", "npm"]).is_err());
        assert!(parse(&["--mitm-config", "/tmp/m.yaml", "npm"]).is_err());
        // Off by default: no interception, no config.
        let cli = parse(&["npm"]).unwrap();
        assert!(!cli.mitm);
        assert!(cli.mitm_config.is_none());
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
