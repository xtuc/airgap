//! The npm profile: package managers run with redaction *and* an interactive
//! file-access gate, so a postinstall script that reads a file outside the
//! project (e.g. `~/.ssh/id_rsa` or `~/.aws/credentials`) must be approved by
//! the user.
//!
//! Everything package-manager-specific lives here — the [`Npm`] profile, the list
//! of npm-family programs, the pre-approved paths, the prompting [`DirGate`], and
//! the terminal prompt — kept out of the generic FUSE overlay (which only knows
//! the [`crate::fs::DirAccess`] trait) and the [`super`] profile interface.

use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::fs::{Access, DirAccess};

use super::{program_basename, DirectoryAccess, Profile};

/// The npm-family package managers this profile applies to, matched by
/// executable basename.
pub const NPM_PROGRAMS: &[&str] = &["npm", "npx", "yarn", "pnpm"];

/// Whether `program` is one of the npm-family package managers.
pub fn is_npm(program: &OsStr) -> bool {
    NPM_PROGRAMS
        .iter()
        .any(|name| program_basename(program) == OsStr::new(name))
}

/// Redaction plus file-access prompting, with the allowlist seeded by the paths
/// package managers routinely touch (see [`preapproved_paths`]).
pub struct Npm;

impl Profile for Npm {
    fn redaction(&self) -> bool {
        true
    }

    fn directory_access(&self) -> DirectoryAccess {
        // Resolved/canonicalized so the entries match the overlay's absolute
        // paths. `$HOME` is dropped if unset or unresolvable; cwd comes from
        // `getcwd` (already canonical).
        let home = std::env::var_os("HOME")
            .filter(|h| !h.is_empty())
            .and_then(|h| std::fs::canonicalize(&h).ok());
        let cwd = std::env::current_dir().ok();
        DirectoryAccess::AskAllowList(preapproved_paths(home.as_deref(), cwd.as_deref()))
    }
}

/// Paths pre-approved for package managers (allowed without prompting) — the
/// benign files and directories npm and friends routinely touch: their log and
/// cache directories and the user's git config under `home`, and the project's
/// `node_modules`, `package.json`, and `package-lock.json` under the working
/// directory `cwd`. A directory entry covers everything beneath it; a file entry
/// matches exactly. Either argument may be `None` if unavailable.
pub fn preapproved_paths(home: Option<&Path>, cwd: Option<&Path>) -> Vec<String> {
    let mut paths = Vec::new();
    if let Some(home) = home {
        paths.push(home.join(".npm/_logs"));
        paths.push(home.join(".npm/_cacache"));
        paths.push(home.join(".npm/_update-notifier-last-checked"));
        paths.push(home.join(".gitconfig"));
        // npm reads the user `.npmrc` for registry/scope config on virtually
        // every command; its credential values are redacted by the FUSE overlay,
        // so allowing the read (rather than prompting each run) is safe.
        paths.push(home.join(".npmrc"));
    }
    if let Some(cwd) = cwd {
        paths.push(cwd.join("node_modules"));
        paths.push(cwd.join("package.json"));
        paths.push(cwd.join("package-lock.json"));
        // The project-local `.npmrc`, likewise redacted.
        paths.push(cwd.join(".npmrc"));
    }
    paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect()
}

/// Obtains a fresh file decision, given the file and the kind of access that
/// triggered it. Production prompts the terminal; tests inject a deterministic
/// stub.
type Asker = Box<dyn Fn(&Path, Access) -> bool + Send + Sync>;

/// Interactive file-access gate. The first time the wrapped program reads,
/// writes, or creates a file not already covered by a decision, the user is
/// prompted to allow or reject *that file*; the answer is cached for the rest of
/// the run. Decisions are matched by path prefix, so a pre-approved (or
/// previously approved) **directory** covers every file beneath it, while a
/// **file** entry matches only itself.
///
/// Directory *listing* is not gated — only file access is — so the prompt always
/// names a specific file.
pub struct DirGate {
    state: Mutex<GateState>,
    ask: Asker,
    /// When set, log each access pre-allowed by the allowlist (a `--debug` aid).
    debug: bool,
}

#[derive(Default)]
struct GateState {
    /// Allowed path prefixes: pre-approved files/dirs plus files the user has
    /// approved. A path is allowed if any entry is a prefix of it.
    allowed: Vec<PathBuf>,
    /// Denied path prefixes (files the user rejected), so a rejected file isn't
    /// re-prompted on every retry.
    denied: Vec<PathBuf>,
}

impl DirGate {
    /// A gate that prompts the controlling terminal, naming `program` in the
    /// prompt so the user knows who is asking. `preapproved` files/directories are
    /// allowed without prompting (directories cover their descendants). With
    /// `debug`, each pre-allowed access is logged to stderr.
    pub fn new(program: String, preapproved: Vec<PathBuf>, debug: bool) -> Self {
        let mut gate = Self::with_asker(
            preapproved,
            Box::new(move |path, access| prompt_tty(&program, path, access)),
        );
        gate.debug = debug;
        gate
    }

    fn with_asker(preapproved: Vec<PathBuf>, ask: Asker) -> Self {
        Self {
            state: Mutex::new(GateState {
                allowed: preapproved,
                denied: Vec::new(),
            }),
            ask,
            debug: false,
        }
    }
}

impl DirAccess for DirGate {
    fn allow(&self, path: &Path, access: Access) -> bool {
        // The decision is about the exact file; it is cached so the same file (or
        // anything under an approved directory) isn't asked again.
        // Held across the prompt so concurrent FUSE requests don't interleave
        // questions on the terminal.
        let mut st = self.state.lock().unwrap();
        if let Some(prefix) = st.allowed.iter().find(|p| path.starts_with(p)) {
            if self.debug {
                eprintln!(
                    "airgap[debug]: pre-allowed {} {} (allowlist: {})",
                    verb(access),
                    path.display(),
                    prefix.display()
                );
            }
            return true;
        }
        if st.denied.iter().any(|p| path.starts_with(p)) {
            return false;
        }
        let decision = (self.ask)(path, access);
        if decision {
            st.allowed.push(path.to_path_buf());
        } else {
            st.denied.push(path.to_path_buf());
        }
        decision
    }
}

/// Prompt on the controlling terminal (`/dev/tty`) rather than the child's
/// stdio, which belongs to the wrapped program. The prompt names the exact file
/// and operation that triggered it. Any failure (no controlling terminal, EOF)
/// fails closed: deny.
fn prompt_tty(program: &str, path: &Path, access: Access) -> bool {
    prompt_tty_inner(program, path, access).unwrap_or(false)
}

/// The verb for an access kind, used in prompts and debug logs.
fn verb(access: Access) -> &'static str {
    match access {
        Access::Read => "read",
        Access::Write => "write",
        Access::Create => "create",
    }
}

fn prompt_tty_inner(program: &str, path: &Path, access: Access) -> std::io::Result<bool> {
    let tty = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    let mut w = &tty;
    write!(
        w,
        "\nairgap: {program} wants to {} the file {} — allow? [y/N] ",
        verb(access),
        path.display()
    )?;
    w.flush()?;
    let mut line = String::new();
    BufReader::new(&tty).read_line(&mut line)?;
    Ok(matches!(line.trim_start().chars().next(), Some('y' | 'Y')))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn detects_npm_programs_by_basename() {
        assert!(is_npm(OsStr::new("npm")));
        assert!(is_npm(OsStr::new("npx")));
        assert!(is_npm(OsStr::new("/usr/bin/yarn")));
        assert!(is_npm(OsStr::new("pnpm")));
        // Not a package manager / not an exact basename.
        assert!(!is_npm(OsStr::new("node")));
        assert!(!is_npm(OsStr::new("claude")));
        assert!(!is_npm(OsStr::new("npm-check")));
    }

    #[test]
    fn preapproves_known_paths() {
        assert_eq!(
            preapproved_paths(Some(Path::new("/home/u")), Some(Path::new("/work/proj"))),
            vec![
                "/home/u/.npm/_logs".to_string(),
                "/home/u/.npm/_cacache".to_string(),
                "/home/u/.npm/_update-notifier-last-checked".to_string(),
                "/home/u/.gitconfig".to_string(),
                "/home/u/.npmrc".to_string(),
                "/work/proj/node_modules".to_string(),
                "/work/proj/package.json".to_string(),
                "/work/proj/package-lock.json".to_string(),
                "/work/proj/.npmrc".to_string(),
            ]
        );
        // Each source contributes independently; both missing ⇒ empty.
        assert_eq!(
            preapproved_paths(None, Some(Path::new("/work/proj"))),
            vec![
                "/work/proj/node_modules".to_string(),
                "/work/proj/package.json".to_string(),
                "/work/proj/package-lock.json".to_string(),
                "/work/proj/.npmrc".to_string(),
            ]
        );
        assert!(preapproved_paths(None, None).is_empty());
    }

    /// A gate (no pre-approved paths) whose answers come from `decide` (called
    /// with the file being accessed), counting how often it's asked.
    fn counting_gate(
        decide: impl Fn(&Path) -> bool + Send + Sync + 'static,
    ) -> (DirGate, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let gate = DirGate::with_asker(
            Vec::new(),
            Box::new(move |path, _access| {
                c.fetch_add(1, Ordering::SeqCst);
                decide(path)
            }),
        );
        (gate, calls)
    }

    #[test]
    fn preapproved_paths_pass_without_prompting() {
        let (gate, calls) = {
            let calls = Arc::new(AtomicUsize::new(0));
            let c = calls.clone();
            let gate = DirGate::with_asker(
                vec![
                    PathBuf::from("/work/proj/node_modules"), // a directory
                    PathBuf::from("/home/u/.gitconfig"),      // a file
                ],
                Box::new(move |_path, _access| {
                    c.fetch_add(1, Ordering::SeqCst);
                    false
                }),
            );
            (gate, calls)
        };
        // Files under a pre-approved directory, and a pre-approved file itself,
        // pass without asking.
        assert!(gate.allow(Path::new("/work/proj/node_modules/dep/index.js"), Access::Read));
        assert!(gate.allow(Path::new("/home/u/.gitconfig"), Access::Read));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        // A file outside any pre-approved path still prompts.
        assert!(!gate.allow(Path::new("/home/u/.ssh/id_rsa"), Access::Read));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn an_approved_file_is_remembered() {
        let (gate, calls) = counting_gate(|_| true);
        assert!(gate.allow(Path::new("/home/u/.npmrc"), Access::Read));
        // Same file again — no second prompt.
        assert!(gate.allow(Path::new("/home/u/.npmrc"), Access::Write));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_denied_file_is_remembered() {
        let (gate, calls) = counting_gate(|_| false);
        assert!(!gate.allow(Path::new("/home/u/.ssh/id_rsa"), Access::Read));
        assert!(!gate.allow(Path::new("/home/u/.ssh/id_rsa"), Access::Read));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn each_file_is_decided_independently() {
        // Approving one file does not cover a sibling: the grant is the exact
        // path, so each distinct file is prompted.
        let (gate, calls) = counting_gate(|_| true);
        assert!(gate.allow(Path::new("/home/u/proj/a.txt"), Access::Read));
        assert!(gate.allow(Path::new("/home/u/proj/b.txt"), Access::Read));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_preapproved_directory_covers_files_under_it() {
        // A directory prefix covers descendants, but not a sibling sharing a
        // string prefix (`proj2` is not under `proj`).
        let (gate, calls) = {
            let calls = Arc::new(AtomicUsize::new(0));
            let c = calls.clone();
            let gate = DirGate::with_asker(
                vec![PathBuf::from("/home/u/proj")],
                Box::new(move |_path, _access| {
                    c.fetch_add(1, Ordering::SeqCst);
                    false
                }),
            );
            (gate, calls)
        };
        assert!(gate.allow(Path::new("/home/u/proj/a/b/c.js"), Access::Read));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(!gate.allow(Path::new("/home/u/proj2/x"), Access::Read));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
