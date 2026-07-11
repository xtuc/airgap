//! Centralized logging: everything airgap emits goes through the `log` facade
//! (`log::{error,warn,info,debug}`) and this module decides where it lands.
//! Logs go to a file (default under `$XDG_STATE_HOME`) so airgap's own
//! diagnostics never interleave with the child's output on the shared terminal;
//! changing the destination is a one-line change here rather than hunting down
//! scattered `eprintln!`s.
//!
//! Levels: warnings and errors always; debug/info only under `--debug`.
//! `RUST_LOG` still overrides both the level and (via env_logger) the filter.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use env_logger::Target;

/// Initialize the global logger. Call once, early in `main` — before entering
/// namespaces (so the file is opened against the real filesystem and its parent
/// can be created) and before any `log::` call. `debug` raises the default level
/// from `warn` to `debug`; `log_file` overrides the default destination.
///
/// Logs are appended to the resolved path. If it can't be opened — or no path
/// can be determined — we fall back to stderr (and say so) so logging never
/// silently disappears.
pub fn init(debug: bool, log_file: Option<PathBuf>) {
    let mut builder = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(if debug { "debug" } else { "warn" }),
    );
    builder.format_timestamp(None);

    match log_file.or_else(default_log_path) {
        Some(path) => match open_log(&path) {
            Ok(file) => {
                builder.target(Target::Pipe(Box::new(file)));
            }
            Err(e) => {
                // Nothing is logging yet, so this notice has to be a direct write.
                eprintln!(
                    "airgap: could not open log file {} ({e}); logging to stderr",
                    path.display()
                );
            }
        },
        None => {
            eprintln!(
                "airgap: no log location ($XDG_STATE_HOME and $HOME both unset; \
                 pass --log-file); logging to stderr"
            );
        }
    }

    builder.init();
}

/// The default log path: `$XDG_STATE_HOME/airgap/airgap.log`, falling back to
/// `~/.local/state/airgap/airgap.log`. `None` if neither env var is usable (the
/// caller then logs to stderr).
fn default_log_path() -> Option<PathBuf> {
    let state = std::env::var_os("XDG_STATE_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|v| !v.is_empty())
                .map(|home| PathBuf::from(home).join(".local/state"))
        })?;
    Some(state.join("airgap").join("airgap.log"))
}

/// Open the log file for appending, creating its parent directory if needed.
/// `O_CLOEXEC` keeps the fd from leaking into the sandboxed child.
fn open_log(path: &Path) -> std::io::Result<File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .custom_flags(nix::libc::O_CLOEXEC)
        .open(path)
}
