//! The AI-agent profile: trusted agents that run with redaction only and
//! unrestricted directory access (no prompts). Also used as the default for
//! `--allow-unknown-program`.

use std::ffi::OsStr;

use super::{program_basename, DirectoryAccess, Profile};

/// AI agents, matched by executable basename.
pub const AI_AGENTS: &[&str] = &["opencode", "claude"];

/// Whether `program` is a trusted AI agent.
pub fn is_ai_agent(program: &OsStr) -> bool {
    AI_AGENTS
        .iter()
        .any(|name| program_basename(program) == OsStr::new(name))
}

/// Redaction only, directories unrestricted.
pub struct AiAgent;

impl Profile for AiAgent {
    fn redaction(&self) -> bool {
        true
    }

    fn directory_access(&self) -> DirectoryAccess {
        DirectoryAccess::AllowAny
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_agents_by_basename() {
        assert!(is_ai_agent(OsStr::new("claude")));
        assert!(is_ai_agent(OsStr::new("/usr/local/bin/opencode")));
        assert!(!is_ai_agent(OsStr::new("npm")));
        assert!(!is_ai_agent(OsStr::new("claude-helper")));
    }
}
