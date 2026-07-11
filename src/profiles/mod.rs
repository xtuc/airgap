//! Per-program profiles: the policy airgap applies to a target program.
//!
//! [`Profile`] is the interface; each concrete profile lives in its own submodule
//! and implements it: [`ai_agents::AiAgent`] for trusted agents (`opencode`,
//! `claude`) and [`npm::Npm`] for package managers (`npm`, `npx`, `yarn`,
//! `pnpm`). A profile describes policy along two axes today —
//! [`Profile::redaction`] and [`Profile::directory_access`] — and the provided
//! [`Profile::directory_gate`] turns the declaration into runtime machinery. More
//! axes (env scrubbing, network mediation) become more trait methods, so the
//! interface stays the single description of "what airgap does to this program".
//!
//! [`resolve`] maps a program's basename to a profile and doubles as the program
//! allowlist (an unrecognized program yields `None`, and the caller rejects it
//! unless `--allow-unknown-program` opts into [`unrestricted`]). [`by_name`]
//! selects a profile explicitly for `--profile`. Adding a profile is adding a
//! submodule here plus a branch in [`resolve`]/[`by_name`].

pub mod ai_agents;
pub mod npm;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::fs::DirAccess;

use ai_agents::AiAgent;
use npm::Npm;

/// How the program may access directories.
pub enum DirectoryAccess {
    /// Any directory may be accessed without asking.
    AllowAny,
    /// Ask the user before accessing a directory that isn't in this pre-approved
    /// allowlist (directory paths, prefix match).
    AskAllowList(Vec<String>),
}

/// The policy airgap applies to a target program. Redaction is the baseline; the
/// other axes are per-profile. Implemented by [`AiAgent`] and [`Npm`].
pub trait Profile {
    /// Whether secret files are redacted on read. True for every profile today —
    /// the baseline guarantee — but part of the interface so it is explicit.
    fn redaction(&self) -> bool;

    /// How the program may access directories.
    fn directory_access(&self) -> DirectoryAccess;

    /// Build the runtime directory gate this profile calls for, if any — the
    /// interactive prompting gate from [`npm`], seeded with the pre-approved
    /// list. `program` only feeds the prompt text. Provided in terms of
    /// [`Self::directory_access`], so implementations just declare the policy.
    fn directory_gate(&self, program: &OsStr) -> Option<Arc<dyn DirAccess>> {
        match self.directory_access() {
            DirectoryAccess::AllowAny => None,
            DirectoryAccess::AskAllowList(allowlist) => {
                let prog = program_basename(program).to_string_lossy().into_owned();
                let preapproved = allowlist.iter().map(PathBuf::from).collect();
                Some(Arc::new(npm::DirGate::new(prog, preapproved)) as Arc<dyn DirAccess>)
            }
        }
    }
}

/// The profile for `program`, or `None` if it is not a recognized program (the
/// caller decides whether to reject it or apply [`unrestricted`]).
pub fn resolve(program: &OsStr) -> Option<Box<dyn Profile>> {
    if npm::is_npm(program) {
        Some(Box::new(Npm))
    } else if ai_agents::is_ai_agent(program) {
        Some(Box::new(AiAgent))
    } else {
        None
    }
}

/// A profile selected explicitly by name via `--profile`, independent of the
/// program (e.g. to exercise directory prompting with a scriptable program in
/// tests). Returns `None` for an unknown name.
pub fn by_name(name: &str) -> Option<Box<dyn Profile>> {
    match name {
        "agent" => Some(Box::new(AiAgent)),
        "npm" => Some(Box::new(Npm)),
        _ => None,
    }
}

/// Default for a program explicitly opted in with `--allow-unknown-program`:
/// redaction only, no directory prompts.
pub fn unrestricted() -> Box<dyn Profile> {
    Box::new(AiAgent)
}

/// The accepted `--profile` names, for the error message.
pub fn names() -> Vec<&'static str> {
    vec!["agent", "npm"]
}

/// The basename of `program` (`/usr/bin/claude` → `claude`), used for matching.
/// Falls back to the whole string if there is no final component.
pub fn program_basename(program: &OsStr) -> &OsStr {
    Path::new(program).file_name().unwrap_or(program)
}

/// Every recognized program name (AI agents + npm package managers), for the
/// "not a recognized program" error message.
pub fn permitted_programs() -> Vec<&'static str> {
    ai_agents::AI_AGENTS
        .iter()
        .copied()
        .chain(npm::NPM_PROGRAMS.iter().copied())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ai_agents_redact_without_directory_prompts() {
        let p = resolve(OsStr::new("claude")).unwrap();
        assert!(p.redaction());
        assert!(matches!(p.directory_access(), DirectoryAccess::AllowAny));
        assert!(p.directory_gate(OsStr::new("claude")).is_none());
        // basename match works for absolute paths too.
        assert!(resolve(OsStr::new("/usr/bin/opencode")).is_some());
    }

    #[test]
    fn package_managers_redact_and_gate_directories() {
        let p = resolve(OsStr::new("npm")).unwrap();
        assert!(p.redaction());
        assert!(matches!(
            p.directory_access(),
            DirectoryAccess::AskAllowList(_)
        ));
        assert!(p.directory_gate(OsStr::new("npm")).is_some());
        assert!(resolve(OsStr::new("/usr/bin/yarn"))
            .unwrap()
            .directory_gate(OsStr::new("yarn"))
            .is_some());
    }

    #[test]
    fn unknown_programs_are_unrecognized() {
        assert!(resolve(OsStr::new("cat")).is_none());
        assert!(resolve(OsStr::new("/bin/sh")).is_none());
    }

    #[test]
    fn by_name_selects_profiles() {
        assert!(matches!(
            by_name("npm").unwrap().directory_access(),
            DirectoryAccess::AskAllowList(_)
        ));
        assert!(matches!(
            by_name("agent").unwrap().directory_access(),
            DirectoryAccess::AllowAny
        ));
        assert!(by_name("nope").is_none());
    }

    #[test]
    fn permitted_list_covers_both_kinds() {
        let list = permitted_programs();
        assert!(list.contains(&"claude"));
        assert!(list.contains(&"opencode"));
        assert!(list.contains(&"npm"));
        assert!(list.contains(&"pnpm"));
    }
}
